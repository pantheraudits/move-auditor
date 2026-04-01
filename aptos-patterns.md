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

## APT-15 — Ordered Map Key Field Ordering (Lexicographic Sort Trap)

**Description:** When a struct is used as a key in `OrderedMap` or `BigOrderedMap`, fields are compared **lexicographically starting from the first declared field** in the struct definition. If the first field isn't your intended primary sort key, every range scan, `borrow_front`, `borrow_back`, and early termination is silently wrong.

**Pattern:**
```move
// VULNERABLE — struct sorts by account first, but code assumes sorting by price
struct OrderKey has copy, drop, store {
    account: address,   // <-- sorts by this first!
    order_id: u64,      // then this
    price: u64,         // this barely matters for ordering
}

// Developer assumes orders are sorted by price — WRONG
// borrow_front returns lowest account address, not lowest price
let cheapest = ordered_map::borrow_front(&orderbook);

// SAFE — put primary sort field first
struct OrderKey has copy, drop, store {
    price: u64,         // primary sort key — first field
    order_id: u64,      // tiebreaker
    account: address,   // least significant
}
```

**Check:**
1. Find every struct used as a key in `OrderedMap` or `BigOrderedMap`
2. Verify the first declared field is the intended primary sort key
3. Check all `borrow_front`, `borrow_back`, and range iteration — do they return what the code expects?
4. No compiler warning, no runtime error — the map works, just not in the order you think

---

## APT-16 — Map Type Selection DoS

**Description:** Aptos has multiple map types with very different performance characteristics. Using the wrong one for permissionless data is a DoS vulnerability.

**Map types and when to use them:**

| Type | Backing | Lookup | Growth | Use for |
|------|---------|--------|--------|---------|
| `SimpleMap` (deprecated) | vector | O(n) linear scan | bounded | Never for permissionless data |
| `OrderedMap` | single slot | O(log n) | bounded | Small bounded sets only |
| `Table` | one slot per key | O(1) | unbounded | Unbounded data, no iteration needed |
| `BigOrderedMap` | B+ tree | O(log n) | unbounded, concurrent | Unbounded data with iteration |

**Pattern:**
```move
// VULNERABLE — SimpleMap with permissionless additions
struct Registry has key {
    users: SimpleMap<address, UserInfo>,  // O(n) lookup, anyone can add
}

public entry fun register(account: &signer) acquires Registry {
    let registry = borrow_global_mut<Registry>(@protocol);
    // Attacker registers thousands of entries
    // Every subsequent lookup/insert costs O(n) gas
    // Eventually: mint, burn, liquidate all bricked
    simple_map::add(&mut registry.users, signer::address_of(account), UserInfo {});
}

// SAFE — use Table or BigOrderedMap for permissionless data
struct Registry has key {
    users: Table<address, UserInfo>,  // O(1) lookup, scales to any size
}
```

**Check:**
1. Flag any `SimpleMap` or `SmartTable` usage — both are deprecated but still in production codebases
2. If the data structure allows permissionless additions (any user can add entries), it MUST use `Table` or `BigOrderedMap`
3. Check if the protocol iterates over the map — `Table` doesn't support iteration; use `BigOrderedMap` if iteration is needed
4. The data structure layer is where some of the highest-impact DoS bugs hide

---

## APT-17 — ConstructorRef Leak

**Description:** When creating Aptos Objects, exposing the `ConstructorRef` allows anyone to generate `TransferRef`, `DeleteRef`, `ExtendRef`, etc. — giving full control over the object. An NFT mint function that returns `ConstructorRef` lets the original creator reclaim the NFT after it's sold.

**Pattern:**
```move
// VULNERABLE — returning ConstructorRef lets caller generate TransferRef
public fun mint(creator: &signer): ConstructorRef {
    let constructor_ref = token::create_named_token(creator, ...);
    constructor_ref  // attacker stores this, generates TransferRef, reclaims NFT after sale
}

// SAFE — never expose ConstructorRef
public fun mint(creator: &signer) {
    let constructor_ref = token::create_named_token(creator, ...);
    // Use constructor_ref internally, then let it go out of scope
}
```

**Check:**
1. No function should return `ConstructorRef` — it's the master key for an object
2. `TransferRef`, `DeleteRef`, `ExtendRef` derived from `ConstructorRef` must be stored securely or not at all
3. If `TransferRef` is stored, verify it's access-gated — otherwise original creator can transfer the object back at will
4. Check NFT minting flows especially — returned refs enable post-sale theft
5. **Ungated transfer control:** If ungated transfers are NOT needed, verify `object::set_untransferable()` is called during construction. Without this, anyone holding a `TransferRef` can move the object freely
6. **DeleteRef discipline:** `DeleteRef` should only be generated for objects that are genuinely intended to be burnable/deletable. Unnecessary `DeleteRef` generation creates object destruction risk — if it leaks or is stored without access control, anyone can permanently destroy the object

*Source: [Aptos Move Security Guidelines](https://aptos.dev/build/smart-contracts/move-security-guidelines)*

---

## APT-18 — Object Account Resource Grouping

**Description:** Multiple `key`-able resources stored at the **same object account** are all transferred together when any one of them is transferred. `object::transfer` operates on `ObjectCore`, which applies to all resources at that address.

**Pattern:**
```move
// VULNERABLE — Monkey and Toad at same object account
fun mint_two(sender: &signer, recipient: address) {
    let constructor_ref = &object::create_object_from_account(sender);
    let obj_signer = object::generate_signer(constructor_ref);
    move_to(&obj_signer, Monkey {});
    move_to(&obj_signer, Toad {});  // same address as Monkey!

    let monkey_obj = object::address_to_object<Monkey>(obj_addr);
    object::transfer(sender, monkey_obj, recipient);
    // BUG: Toad is also transferred — both resources share the object account
}

// SAFE — separate object accounts per resource
fun mint_two(sender: &signer, recipient: address) {
    let ref_monkey = &object::create_object(signer::address_of(sender));
    let ref_toad = &object::create_object(signer::address_of(sender));
    move_to(&object::generate_signer(ref_monkey), Monkey {});
    move_to(&object::generate_signer(ref_toad), Toad {});
    // Now each resource has its own object account — independent transfers
}
```

**Check:**
1. For every `object::create_object` call: how many resources are stored at that object address?
2. If multiple resources share an object account, transferring one transfers ALL — is this intended?
3. Especially dangerous in NFT collections, multi-asset vaults, and gaming items
4. Each independently-transferable resource should have its own object account

*Source: [Aptos Move Security Guidelines](https://aptos.dev/build/smart-contracts/move-security-guidelines)*

---

## APT-19 — Mutable Reference Swap Attack (mem::swap)

**Description:** Passing `&mut T` to untrusted code (callbacks, function values) allows the callee to use `mem::swap` to **replace the entire value** behind the reference. This bypasses private field protections without ever reading or writing them directly.

**Pattern:**
```move
// VULNERABLE — validates asset, passes &mut to untrusted callback, uses asset after
public fun do_with_fa(
    user: address, asset: FungibleAsset, hook: |&mut FungibleAsset|
) {
    check_metadata(&asset);      // verify it's the expected asset
    hook(&mut asset);            // untrusted code: can mem::swap a worthless asset in
    // asset may now be a completely different token!
    primary_fungible_store::deposit(@treasury, asset);  // deposits worthless asset
    mint_to(user, fungible_asset::amount(&asset));      // mints real tokens
}

// SAFE — re-validate after untrusted mutation
public fun do_with_fa(
    user: address, asset: FungibleAsset, hook: |&mut FungibleAsset|
) {
    check_metadata(&asset);
    hook(&mut asset);
    check_metadata(&asset);      // re-check after untrusted code touched it
    // ...
}
```

**Check:**
1. Any `&mut T` passed to a callback, function value, or cross-trust-boundary call — can the callee swap the whole value?
2. Invariants validated before passing `&mut` must be **re-validated after** the call returns
3. Prefer `public(friend)` over `public` for mutation-heavy APIs
4. Don't pass `&mut` to untrusted code at all if possible
5. Especially dangerous for `FungibleAsset`, `Coin`, and any value type used in financial logic

*Source: [Aptos Move Security Guidelines — mem::swap / AIP-105](https://aptos.dev/build/smart-contracts/move-security-guidelines)*

---

## APT-20 — Randomness Bias (Test-and-Abort + Undergasing)

**Description:** Aptos provides on-chain randomness via `aptos_framework::randomness`. Two attack vectors allow biasing outcomes:

1. **Test-and-abort:** If a randomness-using function is `public` (not just `entry`), an attacker composes it with an `assert!` that aborts on unfavorable outcomes. Retry until desired result.
2. **Undergasing:** If favorable and unfavorable code paths consume different gas, attacker sets gas limit that only allows the favorable path to complete. Unfavorable path runs out of gas and aborts.

**Pattern:**
```move
// VULNERABLE — public allows composition with abort-on-bad-outcome
#[lint::allow_unsafe_randomness]
public entry fun play(user: &signer) {
    let random = randomness::u64_range(0, 100);
    if (random == 42) { mint_reward(user); }
}
// Attacker: play(attacker); assert!(exists<Reward>(attacker_addr)); // aborts if lost

// VULNERABLE — win() uses less gas than lose(), attacker limits gas to exclude lose path
#[randomness]
entry fun play(user: &signer) {
    let r = randomness::u64_range(0, 100);
    if (r == 42) { win(user); }    // cheap path
    else { lose(user); }            // expensive path — runs out of gas
}

// SAFE — entry only (not public), equal gas paths
#[randomness]
entry fun play(user: &signer) {
    let r = randomness::u64_range(0, 100);
    // commit random result, resolve in separate tx
    save_result(user, r);
}
```

**Check:**
1. Functions using `randomness::*` must be `entry` only — NOT `public` or `public entry`
2. Favorable and unfavorable code paths must consume similar gas
3. Prefer commit-reveal: save random result in one tx, act on it in a separate tx
4. Only admin-controlled functions should use `#[lint::allow_unsafe_randomness]`

*Source: [Aptos Move Security Guidelines — Randomness](https://aptos.dev/build/smart-contracts/move-security-guidelines)*

---

## APT-21 — Function Value Reentrancy (Move 2.2+)

**Description:** Since Move language version 2.2, function values (closures) enable reentrancy patterns that were previously impossible. While dispatchable fungible assets are protected by reentrancy locks, **function values passed as callbacks are NOT locked**. A callback can re-enter the calling module via dynamic dispatch.

**Mitigations built into Move:**
- Re-entered modules **cannot access their own resources** during dynamic dispatch (attempts to `borrow_global` or `move_from` will abort)
- But attackers can still exploit by altering parameters (e.g., inflating amounts) or swapping values via captured references

**Pattern:**
```move
// VULNERABLE — untrusted function value can re-enter and alter amount
public fun withdraw_operations(
    user: &signer, amount: u64,
    f: |address, &Grant, u64|      // attacker-supplied function value
) {
    let addr = address_of(user);
    assert!(balance(addr) >= amount, E_INSUFFICIENT);
    let g = grant();
    f(addr, &g, amount);           // attacker ignores amount, passes 100_000_000
}

// SAFE — bind amount into a non-droppable Grant at creation time
public fun withdraw_operations(user: &signer, amount: u64, f: |address, Grant|) {
    let addr = address_of(user);
    assert!(balance(addr) >= amount, E_INSUFFICIENT);
    let g = grant(addr, amount);   // state updated + amount fixed inside Grant
    f(addr, g);                    // Grant controls the amount, not the callback
}
```

**Check:**
1. Any function accepting a function value (`|...|` parameter) — can it re-enter the module?
2. Validate that state updates happen BEFORE the callback is invoked (checks-effects-interactions)
3. Don't trust parameters passed to callbacks — bind critical values into non-droppable structs
4. Check for `mem::swap` attacks on `&mut` references captured by closures
5. Dispatchable fungible assets are safe (locked against reentrancy) — other function values are NOT

*Source: [Aptos Move Security Guidelines — Function Values](https://aptos.dev/build/smart-contracts/move-security-guidelines)*

---

## APT-22 — Struct Layout Change on Upgrade

**Description:** When a module is upgraded on Aptos, existing on-chain resources retain
their original binary layout. If struct fields are reordered, removed, or types changed,
deserialization of existing resources fails — all existing user positions become
permanently inaccessible.

**Pattern:**
```move
// v1 — original struct (stored on-chain for all users)
struct Position has key, store {
    owner: address,
    amount: u64,
    debt: u64,
}

// v2 VULNERABLE — field reordered + type changed, existing resources break
struct Position has key, store {
    debt: u128,       // was u64, now u128 — binary layout mismatch
    amount: u64,
    owner: address,   // reordered — deserialization reads wrong bytes
}

// v2 SAFE — append-only changes, existing layout preserved
struct Position has key, store {
    owner: address,   // same order
    amount: u64,      // same type
    debt: u64,        // same type
}

// If migration is needed, use a new struct + migration function
struct PositionV2 has key, store {
    owner: address,
    amount: u64,
    debt: u128,       // upgraded field
}

public entry fun migrate_position(user: &signer) acquires Position {
    let old = move_from<Position>(signer::address_of(user));
    let Position { owner, amount, debt } = old;
    move_to(user, PositionV2 { owner, amount, debt: (debt as u128) });
}
```

**Check:**
1. Compare pre- and post-upgrade struct definitions — field order and types must be preserved
2. If layout changes are needed, a separate V2 struct + migration function must exist
3. Verify migration function handles all existing users (or is callable per-user)
4. New fields can only be appended at the end (append-only compatibility)

---

## APT-23 — Resource Account Signer Scope Creep

**Description:** A `SignerCapability` for a resource account grants unrestricted signer
access to that account. If multiple modules store resources at the same resource account
address, a `SignerCapability` holder can manipulate ALL resources there — not just the
ones their module created.

**Pattern:**
```move
// VULNERABLE — two modules share one resource account
// Module A creates the resource account and stores its signer cap
public fun init_module_a(deployer: &signer) {
    let (resource_signer, cap) = account::create_resource_account(deployer, b"shared");
    move_to(&resource_signer, ModuleAState { value: 0 });
    move_to(deployer, SignerStore { cap }); // Module A holds signer cap
}

// Module B stores resources at the SAME resource account address
public fun init_module_b(admin: &signer) acquires SignerStore {
    let cap = &borrow_global<SignerStore>(@module_a).cap;
    let resource_signer = account::create_signer_with_capability(cap);
    move_to(&resource_signer, ModuleBState { balance: 1000 }); // co-located
}

// Module A can now manipulate Module B's resources!
public fun steal(admin: &signer) acquires SignerStore, ModuleBState {
    let cap = &borrow_global<SignerStore>(@module_a).cap;
    let signer = account::create_signer_with_capability(cap);
    let state = move_from<ModuleBState>(signer::address_of(&signer));
    // Module A just stole Module B's state
}

// SAFE — each module uses its own resource account
public fun init_module_a(deployer: &signer) {
    let (resource_signer, cap) = account::create_resource_account(deployer, b"module_a");
    move_to(&resource_signer, ModuleAState { value: 0 });
    move_to(deployer, SignerStoreA { cap });
}

public fun init_module_b(deployer: &signer) {
    let (resource_signer, cap) = account::create_resource_account(deployer, b"module_b");
    move_to(&resource_signer, ModuleBState { balance: 1000 });
    move_to(deployer, SignerStoreB { cap });
}
```

**Check:**
1. Verify each resource account is used by exactly one module
2. If shared, verify that all modules with `SignerCapability` access are trusted
3. Check that `SignerCapability` is stored privately — not accessible by other modules
4. Cross-ref: APT-04 (signer capability abuse)

---

## APT-24 — Unchecked Signer Parameter (No Address Validation)

**Description:** A `public entry fun` that accepts `&signer` but never validates the signer's address against any stored admin/owner/role address. The `&signer` type only proves someone signed the transaction — it does NOT prove they are authorized. Without a `signer::address_of` comparison, ANY account that signs a transaction can execute the function.

**Pattern:**
```move
// VULNERABLE — &signer accepted but never validated against stored authority
public entry fun set_config(admin: &signer, new_fee: u64) acquires Config {
    let config = borrow_global_mut<Config>(@protocol);
    config.fee = new_fee;
    config.admin = signer::address_of(admin); // sets caller as admin — no check!
}

// VULNERABLE — &signer used only for move_to, anyone can create admin state
public entry fun initialize(account: &signer) {
    move_to(account, AdminConfig {
        admin: signer::address_of(account),
        treasury: signer::address_of(account),
    });
    // No guard: exists<AdminConfig>(@protocol) or one-time init check
}

// SAFE — validates signer address against stored admin
public entry fun set_config(admin: &signer, new_fee: u64) acquires Config {
    let config = borrow_global_mut<Config>(@protocol);
    assert!(signer::address_of(admin) == config.admin, E_NOT_ADMIN);
    config.fee = new_fee;
}
```

**Check:**
1. For every `public entry fun` and `entry fun` that takes `&signer`: search for `signer::address_of` in the function body and all callees
2. If `signer::address_of` is NEVER called, or is called but never compared to a stored/hardcoded authority address → flag as Critical
3. Common false patterns: `signer::address_of` used only as a destination (e.g., `move_to(account, ...)`) but never as an authorization check
4. `init_module(account: &signer)` is a special case — runs once at publish time. But verify it IS `init_module` and not a re-callable setup function

**Risk:** Complete access control bypass. Any wallet can call admin functions, drain funds, change protocol parameters, or take over governance.

*Cross-ref: common-move.md 1.1 (missing capability validation), APT-12 (test functions without restrictions)*

---

## APT-25 — Input Validation Gaps

**Description:** Entry functions that accept user-supplied parameters without validating them against safe ranges. Unlike arithmetic overflow (which Move aborts on), missing input validation allows logically invalid operations to succeed silently — zero-value deposits that corrupt accounting, oversized strings that bloat storage, zero addresses that brick ownership, or out-of-range enum values that bypass intended logic.

**Pattern:**
```move
// VULNERABLE — no input validation, multiple issues
public entry fun create_pool(
    admin: &signer,
    name: String,
    fee_bps: u64,
    recipient: address,
    pool_type: u8,
    initial_tokens: vector<address>
) {
    // name could be empty or 10KB — storage bloat / display issues
    // fee_bps could be 0 (no fees collected) or 100_000 (1000% fee)
    // recipient could be @0x0 — funds sent to unrecoverable address
    // pool_type could be 255 — no enum range check, undefined behavior
    // initial_tokens could be empty — pool created with no assets
}

// SAFE — comprehensive input validation
public entry fun create_pool(
    admin: &signer,
    name: String,
    fee_bps: u64,
    recipient: address,
    pool_type: u8,
    initial_tokens: vector<address>
) {
    // String length
    assert!(string::length(&name) > 0, E_EMPTY_NAME);
    assert!(string::length(&name) <= MAX_NAME_LENGTH, E_NAME_TOO_LONG);

    // Numeric bounds
    assert!(fee_bps > 0, E_ZERO_FEE);
    assert!(fee_bps <= MAX_FEE_BPS, E_FEE_TOO_HIGH);

    // Address validation
    assert!(recipient != @0x0, E_ZERO_ADDRESS);

    // Enum-like range
    assert!(pool_type < NUM_POOL_TYPES, E_INVALID_POOL_TYPE);

    // Vector length
    assert!(vector::length(&initial_tokens) > 0, E_EMPTY_VECTOR);
    assert!(vector::length(&initial_tokens) <= MAX_TOKENS, E_TOO_MANY_TOKENS);
}
```

**Check — 6 validation categories:**
1. **Zero amount:** All `amount: u64` parameters → `assert!(amount > 0, E_ZERO_AMOUNT)`. Zero-value operations can corrupt counters (see APT-13), create empty positions, or bypass minimum thresholds
2. **Max limit:** Numeric inputs bounded by protocol constants → `assert!(amount <= MAX, E_TOO_HIGH)`. Prevents overflow in downstream arithmetic and enforces protocol invariants (e.g., max fee, max leverage)
3. **Vector length:** `assert!(vector::length(&v) > 0, E_EMPTY)` and `assert!(vector::length(&v) <= MAX, E_TOO_MANY)`. Empty vectors cause silent no-ops; unbounded vectors cause gas DoS (see APT-10)
4. **String length:** `assert!(string::length(&s) <= MAX_LENGTH, E_TOO_LONG)`. Unbounded strings bloat on-chain storage and can cause display issues in frontends
5. **Zero address:** `assert!(addr != @0x0, E_ZERO_ADDRESS)`. Setting admin/treasury/recipient to `@0x0` permanently bricks the associated functionality — no private key can sign for `@0x0`
6. **Enum-like range:** `assert!(type_id < NUM_TYPES, E_INVALID_TYPE)`. Out-of-range values on `u8`/`u64` used as type discriminators bypass intended match arms or hit default cases

*Cross-ref: APT-13 (zero-value FA manipulation), APT-10 (vector unbounded growth), common-move.md 2.1 (arithmetic)*

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
- [ ] Ordered map key structs have primary sort field as first declared field (APT-15)
- [ ] No `SimpleMap` / `SmartTable` for permissionless unbounded data — use `Table` or `BigOrderedMap` (APT-16)
- [ ] No function returns or exposes `ConstructorRef` — check NFT mints especially (APT-17)
- [ ] Multiple resources at same object account are intentionally co-transferred (APT-18)
- [ ] `&mut` references re-validated after passing to untrusted code / callbacks (APT-19)
- [ ] Randomness functions are `entry` only (not `public`), equal gas on all paths (APT-20)
- [ ] Function value callbacks cannot re-enter with altered parameters — bind values into structs (APT-21)
- [ ] Struct field order and types preserved across upgrades — append-only or migration function exists (APT-22)
- [ ] Each resource account used by exactly one module — no cross-module signer scope creep (APT-23)
- [ ] Every `public entry fun` / `entry fun` with `&signer` validates address against stored authority — not just used as destination (APT-24)
- [ ] All entry function parameters validated: zero amounts, max limits, vector lengths, string lengths, zero addresses, enum-like ranges (APT-25)
- [ ] Objects that should NOT be freely transferable call `object::set_untransferable()` during construction (APT-17.5/6)
- [ ] `DeleteRef` only generated for objects intended to be burnable — not generated "just in case" (APT-17.6)

### Aptos Build & Test Commands

Run these during Phase 1 build detection when `BUILD_AVAILABLE = true`:

```bash
# Compile — catches type errors, missing acquires, ability violations
aptos move compile

# Run tests — catches logic bugs, assertion failures
aptos move test

# Coverage — target 100% on security-critical modules
aptos move test --coverage
aptos move coverage summary

# Per-module coverage detail
aptos move coverage source --module <module_name>
```

Flag if coverage is below 80% on any module containing `entry fun` or `borrow_global_mut`.
