# Aptos Move — Security Patterns

Aptos-specific vulnerability patterns. Load this when auditing any codebase that imports
`aptos_framework`, `aptos_std`, or uses `#[test_only]` Aptos test annotations.

---

## Aptos Mental Model

Aptos uses a global storage model where resources live at account addresses.
The key concepts creating unique attack surfaces:

- **Global storage** is the primary storage: `move_to`, `move_from`, `borrow_global`, `borrow_global_mut`
- **Signer** represents the transaction sender and is the primary access control primitive
- **Resource accounts** are special accounts controlled by on-chain logic, not private keys
- **Coin & FungibleAsset** frameworks have specific patterns for token handling
- **`acquires` annotations** must exactly match resources accessed
- **Events** are emitted via `event::emit_event` and are critical for off-chain systems

---

## APT-01 — Missing `acquires` Annotation

**Description:** A function that calls `borrow_global` or `borrow_global_mut` on a resource must declare `acquires T`. Missing or incorrect `acquires` annotations cause compile-time errors — but the check: are the `acquires` annotations accurate?

**Pattern:**
```move
// Potentially confusing — acquires annotation on public function
// means any caller indirectly acquires these resources
public fun do_thing(): u64 acquires Config, State {
    let config = borrow_global<Config>(@admin);
    let state = borrow_global<State>(@admin);
    config.value + state.count
}
```

**Check:**
1. Verify that `acquires` annotations match the actual resources accessed (including transitively through helper functions)
2. Functions with large `acquires` lists may have unexpected reentrancy-like behavior if called mid-state-update
3. Public functions with `acquires` expose the resource to the entire call chain

---

## APT-02 — Resource Account Privilege Escalation

**Description:** Resource accounts are controlled by a `SignerCapability`. If this capability is stored insecurely or accessible to unauthorized parties, full control of the resource account is compromised.

**Pattern:**
```move
// VULNERABLE — SignerCapability stored in a globally readable resource
struct ProtocolConfig has key {
    signer_cap: account::SignerCapability,  // anyone can read this!
}

public fun do_admin_thing(caller: &signer) acquires ProtocolConfig {
    let config = borrow_global<ProtocolConfig>(@protocol);
    let resource_signer = account::create_signer_with_capability(&config.signer_cap);
    // resource_signer has full power — but config is readable by anyone
}
```

**Risk:** If `SignerCapability` can be extracted or the resource holding it accessed without proper guards, an attacker gains full control of the resource account.

**Check:**
1. `SignerCapability` should be stored in a resource with access control
2. Functions that use `SignerCapability` to create signers must be admin-gated
3. Verify `SignerCapability` is not accidentally exposed in public structs
4. Check initialization: who receives the `SignerCapability` at creation time?

---

## APT-03 — Coin Type Confusion

**Description:** Generic functions that accept `CoinType` parameters without enforcing which coin types are valid.

**Pattern:**
```move
// VULNERABLE — accepts any coin type as collateral
public entry fun deposit_collateral<CoinType>(
    user: &signer,
    amount: u64
) {
    let coins = coin::withdraw<CoinType>(user, amount);
    // No validation that CoinType is an approved collateral asset!
    add_to_vault<CoinType>(coins);
}
```

**Risk:** Attacker deposits a worthless self-created token as collateral, then borrows
valuable assets against it. Classic DeFi attack.

**Check:**
1. All functions accepting generic `CoinType` must whitelist valid coin types
2. Whitelisting should be enforced on-chain, not just off-chain
3. Price oracles must reject unrecognized coin types
4. `coin::value()` on an unregistered type aborts — but whitelisting should happen before that

*See also: `common-move.md` 8.1 for the general generic type validation pattern*

---

## APT-04 — Signer Capability Abuse (via `create_signer_with_capability`)

**Description:** `account::create_signer_with_capability` creates a real signer that can do anything the resource account can do. Any code path that reaches this function without proper authorization is critical.

**Check:**
1. How many code paths can reach `create_signer_with_capability`?
2. Is each path gated by admin authorization?
3. Can an attacker craft a sequence of calls that reaches this function?
4. Is the resulting signer used only for intended operations?

---

## APT-05 — Table / Iterable Table Safety

**Description:** Aptos `table::Table` and `table_with_length::TableWithLength` have specific safety requirements.

**Patterns:**
```move
// DANGEROUS — table access without existence check
let value = table::borrow(&protocol.balances, user_addr);
// Aborts if key doesn't exist — attacker can DoS by providing non-existent key

// SAFE
assert!(table::contains(&protocol.balances, user_addr), E_NOT_REGISTERED);
let value = table::borrow(&protocol.balances, user_addr);
```

**Check:**
1. All `table::borrow` calls must be preceded by `table::contains` check
2. All `table::remove` calls must be preceded by `table::contains` check
3. Iterating over tables: `TableWithLength` provides length — `Table` does not; verify no unbounded iteration
4. Tables that grow unboundedly (e.g., per-user tables) can cause DoS via storage cost
5. `smart_table` vs `table`: verify the right one is used for the expected access pattern

---

## APT-06 — Timestamp Oracle

**Description:** Aptos provides `timestamp::now_seconds()` and `timestamp::now_microseconds()`.

**Risk:** Block times in Aptos are typically ~1s. Validators have limited ability to adjust timestamps. However:
- Exact timestamp equality checks are fragile
- Time-windows shorter than a few seconds are gameable
- Epoch transitions create predictable timing events

**Pattern:**
```move
// FRAGILE — exact timestamp match never occurs in practice
assert!(timestamp::now_seconds() == deadline, E_NOT_YET);

// BETTER — range check
assert!(timestamp::now_seconds() >= start && timestamp::now_seconds() <= end, E_OUT_OF_WINDOW);
```

**Check:**
1. No exact timestamp equality checks
2. Interest/reward accrual at exact timestamps — check for boundary rounding
3. Lock periods: verify off-by-one on `>` vs `>=` at unlock time
4. Flash loan windows: ensure timestamp-gated operations can't be bypassed by manipulating block timing

---

## APT-07 — Event Handle Exhaustion / Missing Events

**Description:** Aptos uses `EventHandle` for emitting events. Issues arise from:
1. Event handles shared across multiple emitters (counter collisions)
2. Missing events on critical state changes (breaks off-chain monitoring)
3. Events emitted with stale/incorrect data

**Check:**
1. Each logical event source should have its own `EventHandle`
2. Critical state changes (deposits, withdrawals, admin changes) must emit events
3. Event data should reflect post-state (after the change), not pre-state
4. Verify that event emission cannot be skipped via an early return or error path

---

## APT-08 — Module Upgrade Safety

**Description:** Aptos supports module upgrades. Upgrade policies range from `arbitrary` (any upgrade allowed) to `immutable` (no upgrades). Upgrade bugs:

**Check:**
1. What is the upgrade policy? `arbitrary` upgrades are a centralization risk
2. Can storage layout change break existing resources?
3. Does the upgrade add/remove fields in structs that are stored on-chain?
4. Is there a timelock on upgrades? Flag single-key upgrade authority
5. Check for `#[test_only]` functions that were accidentally left accessible in production builds

---

## APT-09 — FungibleAsset Framework vs Legacy Coin

**Description:** Aptos is migrating from `aptos_framework::coin` to `aptos_framework::fungible_asset`. Mixed usage creates compatibility issues.

**Pattern:**
```move
// Protocol mixes frameworks
public entry fun deposit_coin<T>(user: &signer, amount: u64) {
    let coin = coin::withdraw<T>(user, amount);
    // internally converts to FungibleAsset — conversion path must be verified
}
```

**Check:**
1. Identify whether the protocol uses `coin`, `fungible_asset`, or both
2. Conversion between `Coin<T>` and `FungibleAsset` must use official framework functions
3. Balance accounting must be consistent across both frameworks
4. `primary_fungible_store` vs manual store management — verify correct usage

---

## APT-10 — vector / smart_vector Unbounded Growth

**Description:** Vectors that grow unboundedly create DoS vectors through gas exhaustion.

**Pattern:**
```move
struct UserList has key {
    users: vector<address>,  // grows with every new user
}

// Iterating over this in a transaction costs O(n) gas
public entry fun process_all(admin: &signer) acquires UserList {
    let list = borrow_global<UserList>(@protocol);
    let i = 0;
    while (i < vector::length(&list.users)) {
        // O(n) — becomes untransactable as n grows
        process_user(*vector::borrow(&list.users, i));
        i = i + 1;
    }
}
```

**Check:**
1. Any vector that grows with user count is a long-term DoS vector
2. Functions iterating over user-input-sized vectors must have length limits
3. Prefer `smart_table` over `vector<(K, V)>` for key-value lookups
4. Unbounded iteration is a Critical finding if it blocks core protocol functions

---

## APT-11 — `#[view]` Function Side Effect Risks

**Description:** `#[view]` functions should be read-only but if they interact with mutable state patterns, they can cause unexpected behavior.

**Check:**
1. `#[view]` functions must not mutate state
2. Verify `#[view]` functions don't call non-view functions that mutate state
3. View functions used by front-ends for price/balance quotes — ensure they can't be sandwiched

---

## APT-12 — Test / Debug Functions as Privilege Escalation

**Description:** Functions intended for testing that are left accessible in production. Unlike `#[test_only]` functions (which the compiler strips), these are regular `public` functions with names like `test_mint`, `debug_set_admin`, or helper functions that bypass normal access control.

**Pattern:**
```move
// VULNERABLE — test helper left in production, anyone gets admin
public fun test_create_admin(account: &signer): AdminCap {
    // No #[test_only] attribute! Callable in production
    AdminCap { signer_cap: account::create_test_signer_cap(signer::address_of(account)) }
}

// VULNERABLE — init-like function without one-time guard
public entry fun setup_for_testing(admin: &signer) {
    // Meant for tests but callable by anyone — reinitializes protocol
    move_to(admin, Config { fee: 0, admin: signer::address_of(admin) });
}
```

**Check:**
1. Search for functions with `test`, `debug`, `mock`, `setup` in names — are they `#[test_only]`?
2. Any function that creates admin capabilities or signers outside of `init` — is it restricted?
3. Check for `public` functions that set storage directly without access control
4. Verify `#[test_only]` attribute is present on ALL test helper functions and modules

*Real audit ref: Multiple protocols (test code not restricted with #[test_only],
anyone gains admin privileges — Critical)*

---

## APT-13 — FungibleAsset Zero-Value Manipulation

**Description:** Zero-value operations on `FungibleAsset` that corrupt counters, bypass limits, or manipulate investor tracking.

**Pattern:**
```move
// VULNERABLE — zero-value withdrawal increments counter, blocking real withdrawals
public fun withdraw_fa(
    store: &mut FungibleStore,
    amount: u64,
    account: &signer
) acquires WithdrawTracker {
    let tracker = borrow_global_mut<WithdrawTracker>(signer::address_of(account));
    tracker.withdraw_count = tracker.withdraw_count + 1;  // increments even for amount=0
    // If max_withdrawals is 3, attacker sends 3 zero-value txs to block real withdrawals
    assert!(tracker.withdraw_count <= MAX_WITHDRAWALS, E_LIMIT_REACHED);
    fungible_asset::withdraw(account, store, amount);
}

// VULNERABLE — zero-value burn decrements investor count
public fun burn_fa(store: &mut FungibleStore, amount: u64) acquires InvestorTracker {
    let tracker = borrow_global_mut<InvestorTracker>(@protocol);
    tracker.investor_count = tracker.investor_count - 1;  // decrements even for amount=0!
    fungible_asset::burn(store, amount);
}

// SAFE — reject zero-value operations
public fun withdraw_fa(store: &mut FungibleStore, amount: u64, account: &signer) {
    assert!(amount > 0, E_ZERO_AMOUNT);
    // ...
}
```

**Check:**
1. All `fungible_asset::withdraw` / `burn` / `transfer` — what happens with `amount = 0`?
2. Do zero-value operations increment/decrement counters, limits, or tracking variables?
3. Can zero-value deposits create entries that affect reward distribution or voting power?
4. Check `primary_fungible_store` operations for the same zero-value patterns

*Real audit refs: Securitize (zero-value withdrawals block legitimate withdrawals — High,
zero-value burns corrupt investor counts — High)*

---

## APT-14 — Concurrent Privilege Escalation

**Description:** Multiple pending privilege requests (admin, treasury, operator) that can be claimed simultaneously, creating role conflicts or privilege duplication.

**Pattern:**
```move
// VULNERABLE — multiple admins can have pending claims simultaneously
public entry fun claim_admin_privileges(account: &signer) acquires PendingAdmin {
    let pending = borrow_global<PendingAdmin>(@protocol);
    assert!(signer::address_of(account) == pending.new_admin, E_NOT_PENDING);
    // Grants admin — but what if there are two pending requests?
    // Both could claim, creating two admins
}

// VULNERABLE — treasury can also claim admin role
public entry fun claim_admin_privileges(account: &signer) acquires AdminStore {
    let store = borrow_global_mut<AdminStore>(@protocol);
    // No check that caller isn't already treasury — role confusion
    store.admin = signer::address_of(account);
}

// SAFE — cancel previous pending before creating new
public entry fun set_pending_admin(
    admin: &signer,
    new_admin: address
) acquires AdminStore {
    let store = borrow_global_mut<AdminStore>(@protocol);
    assert!(signer::address_of(admin) == store.admin, E_NOT_ADMIN);
    store.pending_admin = option::some(new_admin);
    // Only one pending admin at a time — previous is overwritten
}
```

**Check:**
1. Can multiple privilege transfers be pending simultaneously?
2. Are admin and treasury roles distinct? Can one claim the other's privileges?
3. Does `cancel_admin_privileges` / `cancel_treasury_privileges` have proper access control?
4. Single-step ownership transfer: is it validated? Wrong address = permanent lockout

*Real audit refs: Baptswap (multiple simultaneous pending privileges — High,
cancel_admin callable by anyone — High,
treasury can claim admin — High,
single-step transfer danger — High)*

---

## Aptos Verification Checklist

- [ ] All `table::borrow` / `table::remove` preceded by `table::contains`
- [ ] No generic `CoinType` functions without whitelist enforcement
- [ ] `SignerCapability` stored securely and access-gated
- [ ] No exact timestamp equality checks
- [ ] All critical operations emit events
- [ ] Upgrade policy noted and flagged if `arbitrary`
- [ ] No unbounded vector iteration in public functions
- [ ] Mixed `coin` / `fungible_asset` usage cross-checked
- [ ] `#[test_only]` functions not accessible in production
- [ ] `acquires` annotations verified for accuracy
- [ ] No test/debug/mock functions without `#[test_only]` attribute (APT-12)
- [ ] Zero-value FungibleAsset operations don't corrupt counters or limits (APT-13)
- [ ] No concurrent pending privilege requests that can both be claimed (APT-14)
