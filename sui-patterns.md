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

## SUI-11 — Entry Modifier Visibility Bypass

**Description:** A `public(package) entry` function is callable directly from transactions, bypassing the intended package-only visibility. The `entry` modifier overrides `public(package)` restrictions for direct invocation.

**Pattern:**
```move
// VULNERABLE — entry modifier makes this callable by anyone via transaction
public(package) entry fun emergency_withdraw(
    v: &mut Vault,
    ctx: &TxContext
) {
    v.withdrawals = v.withdrawals + 1;
    v.admin = tx_context::sender(ctx); // attacker becomes admin!
}

// SAFE — without entry, only callable from within the package
public(package) fun emergency_withdraw_secure(
    v: &mut Vault,
    ctx: &TxContext
) {
    v.withdrawals = v.withdrawals + 1;
    v.admin = tx_context::sender(ctx);
}
```

**Check:**
1. Audit every `public(package) entry` function — the `entry` modifier means anyone can call it directly
2. If a function is meant to be package-internal only, remove the `entry` modifier
3. If the `entry` modifier is needed, add explicit authorization checks (admin/capability)

*Source: [Monethic/sui-vuln-lab](https://github.com/Monethic/sui-vuln-lab) — access_control_1*

---

## SUI-12 — Caller Address as Parameter (Spoofable Sender)

**Description:** Functions that accept a caller/sender address as a parameter instead of deriving it from `TxContext`. Anyone can pass any address.

**Pattern:**
```move
// VULNERABLE — caller address is user-supplied, anyone can claim to be admin
public fun withdraw_all(
    v: &mut Vault,
    caller: address,    // attacker passes v.admin address here
) {
    assert!(caller == v.admin, E_NOT_ADMIN);
    v.balance = 0;
}

// SAFE — derive sender from TxContext, cannot be spoofed
public fun withdraw_all(
    v: &mut Vault,
    ctx: &TxContext,
) {
    let caller = tx_context::sender(ctx);
    assert!(caller == v.admin, E_NOT_ADMIN);
    v.balance = 0;
}
```

**Check:**
1. Flag any function that accepts an `address` parameter used for authorization
2. Sender identity must always come from `tx_context::sender(ctx)`
3. Especially dangerous in `public` or `public(package)` functions

*Source: [Monethic/sui-vuln-lab](https://github.com/Monethic/sui-vuln-lab) — access_control_2*

---

## SUI-13 — Phantom Type Generic Role Bypass

**Description:** Role-based capability checks using generic type parameters instead of concrete types. A user holding `RoleCap<UserRole>` can pass it where `RoleCap<ModRole>` or `RoleCap<AdminRole>` was intended.

**Pattern:**
```move
public struct RoleCap<phantom R> has key { id: UID, owner: address }
public struct UserRole has drop {}
public struct AdminRole has drop {}

// VULNERABLE — generic R accepts ANY RoleCap, not just ModRole
public fun moderator_checkout_admin<R>(
    _cap: &RoleCap<R>,          // any user with RoleCap<UserRole> passes this
    ctx: &mut TxContext,
) {
    let admin_cap = RoleCap<AdminRole> { id: object::new(ctx), owner: tx_context::sender(ctx) };
    transfer::transfer(admin_cap, tx_context::sender(ctx));
}

// SAFE — concrete type enforces only ModRole holders can call
public fun moderator_checkout_admin(
    _cap: &RoleCap<ModRole>,    // only RoleCap<ModRole> accepted
    ctx: &mut TxContext,
) {
    let admin_cap = RoleCap<AdminRole> { id: object::new(ctx), owner: tx_context::sender(ctx) };
    transfer::transfer(admin_cap, tx_context::sender(ctx));
}
```

**Check:**
1. Flag any function with generic type parameter on capability structs (e.g., `<R>` in `RoleCap<R>`)
2. Role-gated functions must use concrete types, not generics
3. Verify that `sign_up` / public minting only creates the lowest-privilege capability

*Source: [Monethic/sui-vuln-lab](https://github.com/Monethic/sui-vuln-lab) — access_control_3*

---

## SUI-14 — Table Key Collision (Duplicate Key Abort)

**Description:** Using `table::add` without checking if the key already exists causes an abort on duplicate entries. This can DoS users trying to deposit/interact a second time.

**Pattern:**
```move
// VULNERABLE — aborts on second deposit for the same user
public fun deposit(bank: &mut Bank, user: address, amount: u64) {
    table::add(&mut bank.balances, user, amount); // aborts if key exists!
}

// SAFE — insert-or-update pattern
public fun deposit(bank: &mut Bank, user: address, amount: u64) {
    if (!table::contains(&bank.balances, user)) {
        table::add(&mut bank.balances, user, amount);
    } else {
        let bal = table::borrow_mut(&mut bank.balances, user);
        *bal = *bal + amount;
    }
}
```

**Check:**
1. Every `table::add` call must be preceded by a `table::contains` check or be guaranteed first-time-only
2. Same applies to `bag::add`, `object_bag::add`, `object_table::add`
3. Also check `table::remove` / `table::borrow` without existence checks — they abort on missing keys

*Source: [Monethic/sui-vuln-lab](https://github.com/Monethic/sui-vuln-lab) — tables_1*

---

## SUI-15 — Unbounded Iteration DoS

**Description:** Loops over vectors or tables with user-controlled size. Attackers can grow the data structure until iteration exceeds gas limits, bricking the function.

**Pattern:**
```move
// VULNERABLE — iterates over entire vector, size controlled by users
public fun reward_all(lb: &mut Leaderboard) {
    let len = vector::length(&lb.scores);
    let mut i = 0;
    while (i < len) {
        let s = vector::borrow_mut(&mut lb.scores, i);
        *s = *s + 1;
        i = i + 1;
    }
}

// SAFE — paginated iteration with bounded range
public fun reward_batch(lb: &mut Leaderboard, start: u64, count: u64) {
    let len = vector::length(&lb.scores);
    let end = math::min(start + count, len);
    let mut i = start;
    while (i < end) {
        let s = vector::borrow_mut(&mut lb.scores, i);
        *s = *s + 1;
        i = i + 1;
    }
}
```

**Check:**
1. Flag any `while` or loop that iterates over a vector/table whose size is user-controlled
2. Verify there are caps on how large user-controlled collections can grow
3. Prefer paginated/batched patterns for operations on unbounded collections
4. Check `vector::push_back` calls — is the vector size capped?

*Source: [Monethic/sui-vuln-lab](https://github.com/Monethic/sui-vuln-lab) — tables_2*

---

## SUI-16 — Timestamp Unit Confusion (ms vs seconds)

**Description:** `clock::timestamp_ms()` returns milliseconds but code compares it against constants defined in seconds (or vice versa), breaking time-based locks.

**Pattern:**
```move
const LOCK_TIME_SECONDS: u64 = 10 * 24 * 60 * 60; // 10 days in seconds

// VULNERABLE — stores ms/1000 in stake, but compares raw ms against seconds constant
public entry fun stake(state: &mut StakeState, clock: &Clock, _ctx: &mut TxContext) {
    state.seconds = clock::timestamp_ms(clock) / 1000;  // converted to seconds
    // ...
}

public entry fun unstake(state: &mut StakeState, clock: &Clock, _ctx: &mut TxContext) {
    let now = clock::timestamp_ms(clock);  // raw milliseconds!
    // BUG: comparing ms against (seconds + seconds) — lock is effectively instant
    if (now >= state.seconds + LOCK_TIME_SECONDS) {
        // unlocks immediately because now_ms >> saved_seconds + lock_seconds
    }
}

// SAFE — consistent units throughout
public entry fun unstake(state: &mut StakeState, clock: &Clock, _ctx: &mut TxContext) {
    let now_seconds = clock::timestamp_ms(clock) / 1000;
    if (now_seconds >= state.stake_time_seconds + LOCK_TIME_SECONDS) {
        // correct comparison: seconds vs seconds
    }
}
```

**Check:**
1. Every use of `clock::timestamp_ms()` — verify the result is used consistently (all ms or all seconds)
2. Check constant names vs actual units (e.g., `LOCK_TIME_SECONDS` used with ms values)
3. Flag mixed arithmetic: ms values compared/added to second values
4. Verify struct field names match the units stored in them

*Source: [Monethic/sui-vuln-lab](https://github.com/Monethic/sui-vuln-lab) — time_units*

---

## SUI-17 — Hot Potato State Reset (Nested Flash Loan Attack)

**Description:** Hot potato flash loan patterns where calling `start` multiple times resets the saved snapshot, or where `finish` doesn't actually enforce the return of funds.

**Pattern:**
```move
public fun start_harvest(vault: &mut Vault, ctx: &TxContext): HarvestOp {
    vault.saved_reserves = vault.reserves;  // snapshot resets each call!
    vault.operation_in_progress = true;
    HarvestOp {}
}

// VULNERABLE — finish accepts returned_amount as parameter but doesn't deposit it
public fun finish_harvest(vault: &mut Vault, op: HarvestOp, returned_amount: u64, ctx: &TxContext) {
    let required = vault.saved_reserves * MIN_RETURN_BPS / BPS_DENOM;
    assert!(returned_amount >= required, EInsufficientReturn);
    // BUG: returned_amount is just a number — no actual funds transferred back!
    vault.operation_in_progress = false;
    let HarvestOp {} = op;
}
```

**Attack flow:**
1. Call `start_harvest` → snapshot = 1000, withdraw 900
2. Call `start_harvest` again → snapshot resets to 100 (current reserves)
3. Call `finish_harvest` with `returned_amount = 98` → passes 98% check on 100
4. Attacker keeps 900, vault lost funds

**Check:**
1. `start` function must assert no operation is already in progress (`!operation_in_progress`)
2. Hot potato struct should store the snapshot amount, not the vault
3. `finish` must verify actual token balances, not trust a user-supplied amount parameter
4. Verify the hot potato cannot be created multiple times in the same PTB

*Source: [Monethic/sui-vuln-lab](https://github.com/Monethic/sui-vuln-lab) — hot_potato*

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
- [ ] No `public(package) entry` functions without explicit auth checks (SUI-11)
- [ ] No address parameters used for authorization — sender derived from TxContext (SUI-12)
- [ ] No generic type params on capability-gated functions — concrete types only (SUI-13)
- [ ] All `table::add` / `bag::add` calls guarded by existence checks (SUI-14)
- [ ] No unbounded loops over user-controlled vectors/tables (SUI-15)
- [ ] Timestamp units consistent — no ms/seconds mixing (SUI-16)
- [ ] Hot potato `start` functions assert no operation already in progress (SUI-17)
