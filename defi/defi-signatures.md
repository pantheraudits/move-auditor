# DeFi Signatures & Cryptographic Verification — Move

Vulnerability patterns for signature verification in Move DeFi protocols. Covers
meta-transactions, gasless relays, off-chain authorization, multi-sig, and any
protocol that verifies cryptographic signatures on-chain.

---

## DEFI-74 — Nonce Replay Attack

**Description:** Signatures verified without tracking a nonce can be replayed after
the original transaction. An attacker replays a valid signature to execute the same
operation multiple times (e.g., approve transfer, execute trade, authorize withdrawal).

**Pattern:**
```move
// VULNERABLE — no nonce tracking, signature can be replayed
public fun execute_meta_tx(
    message: vector<u8>,
    signature: vector<u8>,
    public_key: vector<u8>,
) {
    assert!(
        ed25519::ed25519_verify(&signature, &public_key, &message),
        E_INVALID_SIGNATURE
    );
    // Signature verified — but can be submitted again!
    let action = deserialize_action(&message);
    process_action(action);
}

// SAFE — track and increment nonce per signer
public fun execute_meta_tx(
    nonce_store: &mut Table<vector<u8>, u64>,
    message: vector<u8>,
    signature: vector<u8>,
    public_key: vector<u8>,
) {
    assert!(
        ed25519::ed25519_verify(&signature, &public_key, &message),
        E_INVALID_SIGNATURE
    );
    let (action, nonce) = deserialize_action_with_nonce(&message);
    // Verify and increment nonce
    let current = if (table::contains(nonce_store, public_key)) {
        *table::borrow(nonce_store, public_key)
    } else { 0 };
    assert!(nonce == current, E_INVALID_NONCE);
    if (table::contains(nonce_store, public_key)) {
        *table::borrow_mut(nonce_store, public_key) = current + 1;
    } else {
        table::add(nonce_store, public_key, 1);
    };
    process_action(action);
}
```

**Check:**
1. Every signature verification must consume a nonce or mark the signature as used
2. Grep: `ed25519_verify`, `secp256k1_recover`, `verify_signature` — check for nonce logic
3. Alternative: store signature hash in a `Table<vector<u8>, bool>` to prevent replay

---

## DEFI-75 — Cross-Chain Signature Replay

**Description:** A signature valid on Sui can be replayed on Aptos (or vice versa) if
the signed message doesn't include a chain identifier. Same applies across testnets and
mainnets of the same chain.

**Pattern:**
```move
// VULNERABLE — message doesn't include chain ID
public fun verify_authorization(
    message: vector<u8>,  // contains: action + amount + recipient
    signature: vector<u8>,
    public_key: vector<u8>,
) {
    // Same message + signature valid on both Sui mainnet AND Aptos mainnet
    assert!(ed25519::ed25519_verify(&signature, &public_key, &message), E_INVALID);
}

// SAFE — include chain identifier in signed message
public fun verify_authorization(
    message: vector<u8>,  // contains: chain_id + contract_address + action + amount + recipient
    signature: vector<u8>,
    public_key: vector<u8>,
    expected_chain_id: u64,
) {
    assert!(ed25519::ed25519_verify(&signature, &public_key, &message), E_INVALID);
    let (chain_id, contract_addr, _action) = deserialize_message(&message);
    assert!(chain_id == expected_chain_id, E_WRONG_CHAIN);
    // On Sui: also verify contract address matches this package ID
    // On Aptos: verify module address matches
}
```

**Check:**
1. Does the signed message include a chain identifier (chain ID or chain name)?
2. Does it include the contract/module address to prevent replay on different deployments?
3. Check: same protocol deployed on both Sui and Aptos — can signatures be shared?
4. Cross-ref: DEFI-10

---

## DEFI-76 — Missing Parameters in Signed Message

**Description:** Critical parameters not included in the signed message can be
manipulated by the transaction submitter. If the message includes `amount` but
not `recipient`, the submitter can redirect funds to any address.

**Pattern:**
```move
// VULNERABLE — message missing recipient, submitter can redirect
// Signed message: hash(action, amount, nonce)
// Attacker changes recipient to their own address — signature still valid
public fun execute_transfer(
    amount: u64,
    recipient: address,  // NOT in signed message — attacker-controlled
    nonce: u64,
    signature: vector<u8>,
    public_key: vector<u8>,
) {
    let message = bcs::to_bytes(&TransferMsg { amount, nonce }); // recipient missing!
    assert!(ed25519::ed25519_verify(&signature, &public_key, &message), E_INVALID);
    transfer_tokens(amount, recipient);
}

// SAFE — all mutable parameters included in signature
public fun execute_transfer(
    amount: u64,
    recipient: address,
    nonce: u64,
    deadline: u64,
    signature: vector<u8>,
    public_key: vector<u8>,
) {
    let message = bcs::to_bytes(&TransferMsg { amount, recipient, nonce, deadline });
    assert!(ed25519::ed25519_verify(&signature, &public_key, &message), E_INVALID);
    transfer_tokens(amount, recipient);
}
```

**Check:**
1. List ALL parameters that affect the outcome of the signed operation
2. Every such parameter must be included in the signed message
3. Common missing parameters: recipient, deadline, chain_id, contract address, token type
4. If using BCS serialization, verify field order matches between signer and verifier

---

## DEFI-77 — No Expiration on Signatures

**Description:** Signatures without a deadline/expiration are valid forever. If a
user's permission is revoked (e.g., removed from whitelist, KYC expired), old
signatures still work — granting "lifetime access" that cannot be revoked.

**Pattern:**
```move
// VULNERABLE — signature never expires
public fun claim_with_signature(
    amount: u64,
    signature: vector<u8>,
    public_key: vector<u8>,
) {
    let message = bcs::to_bytes(&ClaimMsg { amount });
    assert!(ed25519::ed25519_verify(&signature, &public_key, &message), E_INVALID);
    // This signature works forever — even after airdrop period ends
    mint_tokens(amount);
}

// SAFE — include deadline in signed message
public fun claim_with_signature(
    amount: u64,
    deadline: u64,
    signature: vector<u8>,
    public_key: vector<u8>,
    clock: &Clock,
) {
    assert!(clock::timestamp_ms(clock) <= deadline, E_SIGNATURE_EXPIRED);
    let message = bcs::to_bytes(&ClaimMsg { amount, deadline });
    assert!(ed25519::ed25519_verify(&signature, &public_key, &message), E_INVALID);
    mint_tokens(amount);
}
```

**Check:**
1. Every signed message should include a `deadline` or `expires_at` field
2. The deadline must be checked BEFORE processing the action
3. For long-lived authorizations, consider a revocation mechanism instead

---

## DEFI-78 — Unchecked Signature Verification Return Value

**Description:** Move's `ed25519::ed25519_verify` returns a `bool`. If the code
calls it but doesn't check the return value, ALL signatures pass verification.
This is a critical authentication bypass.

**Pattern:**
```move
// VULNERABLE — return value ignored, all signatures accepted
public fun verify_and_execute(
    message: vector<u8>,
    signature: vector<u8>,
    public_key: vector<u8>,
) {
    // Returns bool but not checked! Any signature passes
    ed25519::ed25519_verify(&signature, &public_key, &message);
    execute_privileged_action();
}

// SAFE — assert on return value
public fun verify_and_execute(
    message: vector<u8>,
    signature: vector<u8>,
    public_key: vector<u8>,
) {
    let valid = ed25519::ed25519_verify(&signature, &public_key, &message);
    assert!(valid, E_INVALID_SIGNATURE);
    execute_privileged_action();
}
```

**Check:**
1. Every call to signature verification must assert on the return value
2. Grep: `ed25519_verify`, `ecdsa_recover` — verify return is used in `assert!`
3. On Aptos: `ed25519::signature_verify_strict` also returns `bool`
4. Cross-ref: common-move.md 6.3 (unvalidated return values)

---

## DEFI-79 — Signature Malleability (secp256k1)

**Description:** secp256k1 ECDSA signatures have a malleability property: for any
valid signature `(r, s)`, the signature `(r, n-s)` is also valid (where `n` is the
curve order). If raw signature bytes are used as unique keys (e.g., in a replay
prevention table), the malleated signature bypasses the check.

**Pattern:**
```move
// VULNERABLE — using raw signature as replay prevention key
public fun execute_once(
    used_sigs: &mut Table<vector<u8>, bool>,
    message: vector<u8>,
    signature: vector<u8>,
) {
    assert!(!table::contains(used_sigs, signature), E_ALREADY_USED);
    // Attacker submits (r, s) — marked as used
    // Then submits (r, n-s) — different bytes, same signer, bypasses check!
    let pk = ecdsa_k1::secp256k1_ecrecover(&signature, &message, 0);
    assert!(pk == EXPECTED_SIGNER, E_WRONG_SIGNER);
    table::add(used_sigs, signature, true);
    execute_action();
}

// SAFE — normalize s-value, or use message hash as key instead
public fun execute_once(
    used_msgs: &mut Table<vector<u8>, bool>,
    message: vector<u8>,
    signature: vector<u8>,
) {
    let msg_hash = hash::sha3_256(message);
    assert!(!table::contains(used_msgs, msg_hash), E_ALREADY_USED);
    let pk = ecdsa_k1::secp256k1_ecrecover(&signature, &message, 0);
    assert!(pk == EXPECTED_SIGNER, E_WRONG_SIGNER);
    // Key by message hash, not signature — malleability doesn't matter
    table::add(used_msgs, msg_hash, true);
    execute_action();
}
// Note: ed25519 in Move uses strict verification which is NOT malleable
```

**Check:**
1. If using secp256k1: verify s-value normalization or use message hash as replay key
2. If using ed25519: `ed25519_verify` with strict mode is safe from malleability
3. Never use raw signature bytes as a unique identifier
4. Check if protocol uses `secp256k1_ecrecover` — search for `ecdsa_k1`, `secp256k1`

---

## DEFI-89 — Signatures Verified Against Live Policy Instead of the Policy at Signing Time

**Description:** When an authorization scheme verifies a set of signatures against
**mutable on-chain policy state** — the signer set, the approval threshold, a quorum, an
allowlist, a role table — but that policy can change between the moment signatures are
collected off-chain and the moment they are submitted on-chain, the signatures are
effectively re-interpreted under whatever policy is current at execution. The signed
payload binds *what* is being authorized (amount, recipient, nonce) but not *which policy*
the signatures were meant to satisfy.

This creates a **stale partial-approval** problem: a request that was deliberately
*not* executable when signatures were gathered (e.g. only 2 of a required 3 signers signed)
can silently become executable later after a routine policy update (threshold lowered to 2,
or the signer set narrowed) — even though no new approval for that specific request was ever
collected under the new policy. It is the dual of DEFI-76 (missing params in the signed
message): here the missing bound is the *verification policy itself*, not a call parameter.

This is **not** the same as nonce replay (DEFI-74). The request may have a perfectly good
per-request nonce and still be unused — the problem is that the threshold/signer-set the
signatures are checked against is read from live, admin-mutable state rather than snapshotted
into the signed message.

**Pattern:**
```move
// VULNERABLE — threshold and signer set read from current (mutable) config,
// not from the policy that existed when signatures were produced.
public struct Config has key, store {
    id: UID,
    signers: vector<vector<u8>>,  // mutated by add_signer / remove_signer / reset_signers
    threshold: u64,               // mutated by set_threshold
    // ... no policy version / nonce
}

public fun withdraw(
    config: &Config,
    vault: &mut Vault,
    amount: u64,
    recipient: address,
    request_nonce: u64,
    signatures: vector<vector<u8>>,
    ctx: &mut TxContext,
) {
    // Signed message binds the request, but NOT the policy it must satisfy:
    let message = build_message(amount, recipient, request_nonce);

    // Count is compared against the LIVE threshold and LIVE signer set:
    assert!(signatures.length() >= config.threshold, EINVALID_SIGNATURES);
    assert!(signatures.length() <= config.signers.length(), EINVALID_SIGNATURES);
    let mut valid = 0; let mut i = 0;
    while (i < config.signers.length()) {
        if (verify(config.signers.borrow(i), &message, &signatures)) { valid = valid + 1; };
        i = i + 1;
    };
    assert!(valid >= config.threshold, ETHRESHOLD_TOO_LOW); // <-- live threshold
    release_funds(vault, amount, recipient);
}
// Attack: collect 2 of 3 required sigs -> request not yet submitted ->
// owner routinely lowers threshold to 2 (or drops the 3rd signer) ->
// old 2 sigs now satisfy the new policy -> funds released without new approval.

// SAFE — bind the policy version into the signed message and require the caller
// to assert it matches the current policy. Every signer/threshold mutation bumps it.
public struct Config has key, store {
    id: UID,
    signers: vector<vector<u8>>,
    threshold: u64,
    signer_policy_nonce: u64,     // bumped in add_signer/remove_signer/reset_signers/set_threshold
}

public fun withdraw(
    config: &Config,
    vault: &mut Vault,
    amount: u64,
    recipient: address,
    request_nonce: u64,
    expected_policy_nonce: u64,
    signatures: vector<vector<u8>>,
    ctx: &mut TxContext,
) {
    // Reject signatures produced under a stale policy outright:
    assert!(expected_policy_nonce == config.signer_policy_nonce, ESTALE_POLICY);
    // Bind the policy version into the signed payload so sigs can't be re-interpreted:
    let message = build_message(amount, recipient, request_nonce, config.signer_policy_nonce);
    // ... threshold / signer checks as before
}
```

**Check:**
1. Find every authorization path that verifies signatures (or counts approvals) against
   state read from a struct — grep the signer set / threshold / quorum / allowlist fields:
   `threshold`, `signers`, `quorum`, `min_signatures`, `weight`, `approvers`, `guardians`,
   `voting_power`, `role`, `whitelist`.
2. For each such field, find all writers: `add_signer`, `remove_signer`, `reset_signers`,
   `set_threshold`, `update_signers`, `rotate`, `set_quorum`, governance/admin setters.
   If **any** writer exists, the policy is mutable.
3. Now ask: **is the policy version bound into the signed message?** Trace the message
   builder / hash (`build_message`, `keccak`, `hash::*`, `bcs::to_bytes`). If the message
   does NOT include a policy nonce / version / snapshot, the signatures float against live
   state → finding.
4. Confirm the time gap is real: signatures are gathered off-chain (any multi-sig, gasless
   relay, or off-chain quorum) and submitted in a separate transaction. A scheme where the
   signers sign *and* execute in the same atomic step is not exposed.
5. Severity: **High** when funds/privileged actions are released and a threshold reduction
   or signer-set change can revive a sub-threshold request (loss of funds without fresh
   approval); Medium if the action is reversible or non-financial.

**Fix:** Add a monotonic `signer_policy_nonce` (or version) to the policy struct, increment
it in **every** signer/threshold/quorum mutation, include it in the signed message, and
require the caller to pass the expected nonce so stale-policy signatures are rejected. If a
per-message policy version is infeasible, invalidate all outstanding authorizations on any
policy change via a global authorization nonce that is also bound into the signed message.

**Cross-ref:** DEFI-76 (missing params in signed message — same root class, different missing
bound), DEFI-74 (nonce replay — distinct: a request can be unused yet still mis-validated here),
DEFI-77 (no expiration — a deadline narrows but does not close this window).

---

## Signature Verification Checklist

- [ ] Every signature verification tracks and consumes a nonce (DEFI-74)
- [ ] Signed messages include chain ID and contract address (DEFI-75)
- [ ] All outcome-affecting parameters are included in signed message (DEFI-76)
- [ ] Signatures include expiration deadline (DEFI-77)
- [ ] Signature verification return value is asserted, never ignored (DEFI-78)
- [ ] secp256k1 replay prevention uses message hash, not raw signature bytes (DEFI-79)
- [ ] Signatures are bound to the signer-set/threshold policy version in effect when they were collected, not re-checked against live mutable policy state (DEFI-89)
