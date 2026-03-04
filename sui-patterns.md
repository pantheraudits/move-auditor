# Sui Move — Security Patterns

Sui-specific vulnerability patterns. Load this when auditing any codebase that imports
`sui::object`, `sui::transfer`, or `sui::tx_context`.

---

## Sui Mental Model

Sui's object-centric model is fundamentally different from account-based Move (Aptos).
The key concepts that create unique attack surfaces:

- **Objects** are the primary unit of storage, not global storage at addresses
- **Ownership** is tracked by the Sui runtime: objects can be owned, shared, immutable, or wrapped
- **Shared objects** require consensus; owned objects don't
- **Capability pattern** is the primary access control mechanism
- **Witness pattern** is used for one-time type initialization

Misunderstanding any of these leads to exploitable vulnerabilities.

---

## SUI-01 — Object Ownership Confusion

**Description:** Functions that accept object references without verifying the caller owns them.

**Pattern:**
```move
// VULNERABLE — accepts any Coin object regardless of ownership
public entry fun deposit(pool: &mut Pool, coin: Coin<SUI>, ctx: &mut TxContext) {
    // No check that coin belongs to tx sender
    pool::add_liquidity(pool, coin);
}
```

**Risk:** In Sui, object ownership is enforced by the runtime at the transaction level —
you can't pass an owned object you don't own. However, shared objects and wrapped objects
can create confusion. Check for:

1. Shared objects where callers can manipulate state they shouldn't
2. Functions that accept `&mut T` on a shared object without validating caller permissions
3. Hot potato patterns (structs without `drop`) that can be passed between functions unexpectedly

**Check:** For every function accepting a mutable shared object, verify there is an explicit
permission/capability check before mutation.

---

## SUI-02 — Shared Object Reentrancy / State Inconsistency

**Description:** Shared objects accessed in a partially-updated state during a PTB (Programmable Transaction Block).

**Pattern:** A PTB calls `function_A` which partially updates shared object `S`, then calls
`function_B` which reads `S` before `function_A` completes its invariant restoration.

**Risk:** While Sui doesn't have EVM reentrancy, PTBs allow chaining of function calls.
If a shared object is left in inconsistent state mid-PTB, subsequent calls in the same
PTB can observe and exploit that state.

**Check:**
- Every function that modifies a shared object should leave it in a valid state after each call
- Watch for "unlock then use" patterns where the unlock and use happen in separate PTB steps
- Flash loan implementations must enforce that loans are repaid within the same PTB

---

## SUI-03 — Witness Pattern Abuse

**Description:** The witness pattern (`struct Witness has drop {}`) is used to prove type ownership at initialization. Bugs arise when witnesses can be created without the expected constraints.

**Pattern:**
```move
// VULNERABLE — witness struct is public and copyable
public struct MY_WITNESS has copy, drop {}

// Anyone can create a witness and call privileged functions
public fun create_with_witness(w: MY_WITNESS) { ... }
```

**Risk:** If the witness type has `copy`, anyone can call privileged initialization functions
multiple times or from unexpected modules.

**Check:**
1. One-Time Witness (OTW) structs must have the exact module name in ALL_CAPS
2. OTW structs must have only `drop` ability — never `copy` or `store`
3. OTW structs must be consumed (not referenced) in the privileged function
4. The `sui::types::is_one_time_witness` check should be used where applicable

---

## SUI-04 — Transfer to Wrong Owner

**Description:** Objects transferred to an attacker-controlled address due to missing sender validation.

**Pattern:**
```move
// VULNERABLE — recipient is user-supplied
public entry fun claim_reward(
    pool: &mut Pool,
    recipient: address,  // attacker-controlled!
    ctx: &mut TxContext
) {
    let reward = calculate_reward(pool);
    transfer::public_transfer(reward, recipient);
}
```

**Check:** Functions that transfer objects or coins to an address should validate that the
recipient is the transaction sender, or that the caller has explicit permission to specify
a different recipient.

---

## SUI-05 — Wrapping and Unwrapping Attacks

**Description:** Objects can be wrapped inside other objects and become inaccessible without being destroyed. Malicious actors can trap objects.

**Pattern:**
```move
// If an NFT can be wrapped into any arbitrary struct,
// a malicious contract could wrap it and never unwrap
public entry fun wrap_nft(nft: SomeNFT, wrapper: &mut MaliciousWrapper) {
    wrapper.trapped_nft = option::some(nft);
    // nft is now trapped — original owner loses access
}
```

**Risk:** Protocol-level object wrapping that doesn't have a guaranteed unwrap path.
Flash loans that wrap the collateral in a non-unwrappable struct.

**Check:**
- Any wrapping function should have a corresponding, accessible unwrapping function
- Objects that hold other objects must provide guaranteed extraction paths
- Flash loan implementations: verify the "repay" step unwraps any wrapped collateral

---

## SUI-06 — Dynamic Field Injection

**Description:** Dynamic fields allow attaching arbitrary data to objects at runtime.
If a shared object accepts dynamic field additions from any caller, attackers can
pollute the object's field namespace.

**Pattern:**
```move
// VULNERABLE — any caller can add fields to shared object
public entry fun add_metadata(
    obj: &mut SharedProtocolObject,
    key: String,
    value: String,
    ctx: &mut TxContext
) {
    dynamic_field::add(&mut obj.id, key, value);
}
```

**Risk:**
1. Field namespace collision (overwriting existing fields)
2. Storage bloat as an attack (adding thousands of fields)
3. Polluting protocol state with attacker-controlled data

**Check:**
- Dynamic field additions to shared objects should be permissioned
- Keys should be namespaced to prevent collisions
- Removal paths should exist to prevent permanent storage bloat

---

## SUI-07 — Clock / Epoch Oracle Manipulation

**Description:** Logic that relies on `sui::clock::Clock` for time-sensitive operations.

**Pattern:**
```move
// Auction with time-based mechanics
public entry fun place_bid(
    auction: &mut Auction,
    clock: &Clock,
    bid: Coin<SUI>,
    ctx: &mut TxContext
) {
    assert!(clock::timestamp_ms(clock) < auction.end_time, E_AUCTION_ENDED);
    // ...
}
```

**Risk:** Validators can influence block timestamps by small amounts (~few hundred ms).
Epoch boundaries can be predicted. Flash loan attacks can be constructed around epoch transitions.

**Check:**
1. Time windows shorter than 1000ms are potentially manipulable by validators
2. Logic at epoch boundaries (staking rewards, interest accrual) must handle the exact boundary case
3. Avoid `clock::timestamp_ms() == exact_value` checks — always use ranges
4. Flag any "last second" scenarios where timestamp manipulation gives economic benefit

---

## SUI-08 — Capability Object Theft / Forgery

**Description:** Capability objects that can be created, copied, or obtained by unauthorized parties.

**Pattern:**
```move
// VULNERABLE — AdminCap can be minted by anyone
public fun create_admin_cap(): AdminCap {
    AdminCap { id: object::new(ctx) }
}
```

**Check:**
1. Capability creation should only happen in `init()` (called once at deployment)
2. Capability structs should never have `copy` ability
3. Capability transfer should be restricted — not `public_transfer`
4. Check if `TreasuryCap` (for coins) is properly stored and access-controlled

---

## SUI-09 — Hot Potato Misuse

**Description:** Hot potato structs (no abilities) must be consumed in the same PTB. Misuse creates DoS or loss of funds.

**Pattern:**
```move
struct HotPotato { value: u64 }  // no abilities

// If the function that creates HotPotato panics before the consuming function
// is called in the PTB, the user's transaction fails and any sent funds may be locked
```

**Check:**
1. Hot potato patterns in flash loans: verify both "take" and "return" functions work correctly
2. If a hot potato is created but the transaction aborts, verify no funds are lost
3. The "repay" path for hot-potato flash loans must be accessible in the same PTB

---

## SUI-10 — Event Spoofing

**Description:** Events emitted with attacker-controlled data that downstream off-chain systems trust.

**Risk:** If a protocol's off-chain infrastructure (indexers, bridges, relayers) trusts emitted events without verification, attackers can emit fake events to trigger off-chain actions.

**Check:**
- Events emitted from privileged operations should only be reachable through privileged paths
- Off-chain systems should verify on-chain state, not just events

---

## Sui Verification Checklist

- [ ] All shared object mutations are permission-gated
- [ ] No OTW structs with `copy` ability
- [ ] No unconstrained transfer-to-address functions
- [ ] All wrapped objects have guaranteed unwrap paths
- [ ] Dynamic field additions to shared objects are permissioned
- [ ] Time-sensitive logic uses >1000ms windows
- [ ] Capability creation only in `init()`
- [ ] Hot potato flash loans tested for abort-safety
- [ ] TreasuryCap access-controlled
- [ ] Events not trusted as primary source of truth by critical systems
