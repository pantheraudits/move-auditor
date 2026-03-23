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

## SUI-18 — Missing Object / UID Validation

**Description:** Functions that accept Sui objects without validating their UID or origin. Attackers create their own instance of the same struct type with manipulated internal values.

**Pattern:**
```move
// VULNERABLE — no validation that bank is the legitimate protocol instance
public fun mint_shares(
    bank: &mut Bank,
    amount: u64,
    ctx: &mut TxContext
) {
    // Attacker creates a fake Bank with share_price = 1
    let shares = amount * PRECISION / bank.share_price;
    // Shares minted at manipulated price
}

// SAFE — validate object ID against a registry or known ID
public fun mint_shares(
    bank: &mut Bank,
    registry: &Registry,
    amount: u64,
    ctx: &mut TxContext
) {
    assert!(object::id(bank) == registry.bank_id, E_INVALID_BANK);
    let shares = amount * PRECISION / bank.share_price;
}
```

**Check:**
1. Functions accepting objects that determine prices, rates, or permissions — is the object ID validated?
2. Can an attacker create their own instance of a shared object type and pass it?
3. Functions referencing multiple objects — verify they belong to the same protocol instance
4. Especially critical for objects used as price sources or liquidity pools

*Real audit refs: Bluefin (no UID validation, forged BankV2 — Critical),
Kuna Labs (different SupplyPool instances referenced — High)*

---

## SUI-19 — Unconditional Balance Destruction

**Description:** Calling `balance::destroy_zero()` on a balance that may not be zero, permanently destroying remaining funds.

**Pattern:**
```move
// VULNERABLE — assumes remaining balance is zero after liquidation
public fun liquidate(position: &mut Position) {
    let seized = balance::split(&mut position.collateral, liquidation_amount);
    // ... transfer seized to liquidator ...

    let leftover = balance::withdraw_all(&mut position.collateral);
    balance::destroy_zero(leftover);
    // ABORTS if any collateral remains, or DESTROYS funds if called unsafely
}

// SAFE — handle non-zero remainder
public fun liquidate(position: &mut Position, ctx: &mut TxContext) {
    let seized = balance::split(&mut position.collateral, liquidation_amount);
    // ... transfer seized to liquidator ...

    let leftover = balance::withdraw_all(&mut position.collateral);
    if (balance::value(&leftover) > 0) {
        transfer::public_transfer(
            coin::from_balance(leftover, ctx),
            position.owner
        );
    } else {
        balance::destroy_zero(leftover);
    }
}
```

**Check:**
1. Every `balance::destroy_zero()` / `coin::destroy_zero()` — is the balance **guaranteed** to be zero?
2. Common in liquidation flows where remaining collateral may not be exactly zero
3. Also check `balance::split` where the split amount could exceed the balance (causes abort)
4. Partial liquidation: remainder must be returned to the position owner

*Real audit ref: Creek Finance (unconditional destroy_zero on non-zero balances during liquidation — High)*

---

## SUI-20 — Flash Loan Receipt Pool Binding

**Description:** Sui flash loan receipts (hot potatoes) that don't bind to their originating pool via `object::id`. This is the Sui-specific variant of the generic type confusion pattern (see `common-move.md` 8.1) — on Sui, the key check is validating the pool's `ID` inside the receipt.

**Pattern:**
```move
struct FlashReceipt { pool_id: ID, amount: u64 }

// VULNERABLE — doesn't verify receipt.pool_id matches this pool
public fun repay_flash_loan<T>(
    pool: &mut Pool<T>,
    receipt: FlashReceipt,
    payment: Coin<T>,
) {
    assert!(coin::value(&payment) >= receipt.amount, E_UNDERPAY);
    balance::join(&mut pool.reserve, coin::into_balance(payment));
    let FlashReceipt { pool_id: _, amount: _ } = receipt;
    // Attacker borrows from Pool A, repays to Pool B
}

// SAFE — validate receipt belongs to this specific pool via object::id
public fun repay_flash_loan<T>(
    pool: &mut Pool<T>,
    receipt: FlashReceipt,
    payment: Coin<T>,
) {
    assert!(receipt.pool_id == object::id(pool), E_WRONG_POOL);
    assert!(coin::value(&payment) >= receipt.amount, E_UNDERPAY);
    balance::join(&mut pool.reserve, coin::into_balance(payment));
    let FlashReceipt { pool_id: _, amount: _ } = receipt;
}
```

**Check:**
1. Receipt struct must store the originating pool's `ID` (set via `object::id(pool)` at borrow time)
2. Repay function must assert `receipt.pool_id == object::id(pool)`
3. Receipt must be consumed (destructured) — not just read by reference
4. Repayment amount must account for fees
5. Can the same receipt be used across different pools in a PTB?

*Real audit refs: Cetus (repay_flash_loan doesn't verify order_id — Critical),
Dexlyn (repay_flash_swap missing pool binding — Critical)*

---

## SUI-21 — Denylist Enforcement Awareness (Validator-Level + Epoch Gap)

**Description:** Sui's regulated coin denylist (`DenyCapV2`) is enforced at the **validator level during transaction input validation**, not in Move code. This creates two auditor-relevant behaviors:

1. **Sending is blocked instantly** — a blocked user cannot submit a transaction using their regulated coins as inputs. The tx fails before Move code runs.
2. **Receiving is only blocked at next epoch (~24hrs)** — a blocked user can still receive coins until the epoch changes.

**Risk:** The epoch gap for receiving creates a dangerous window in cross-chain scenarios. If tokens are burned on a source chain and minting is attempted on destination after epoch change, funds can be lost permanently.

```move
// FALSE POSITIVE — this is NOT a bypass
// A blocked user calling transfer directly will fail at the validator level
// before this Move code ever executes
public fun transfer_coins(coin: Coin<REGULATED>, recipient: address) {
    // No denylist check needed here — validators enforce it
    transfer::public_transfer(coin, recipient);
}

// REAL RISK — cross-chain bridge: burn on source, mint on destination
// If user is blocked between burn and mint, funds are lost
public fun bridge_mint(proof: BurnProof, recipient: address, ctx: &mut TxContext) {
    // recipient was allowed when burn happened on source chain
    // but may be blocked by the time this mints on Sui (epoch changed)
    let coin = coin::mint(&mut treasury, proof.amount, ctx);
    transfer::public_transfer(coin, recipient);  // recipient now blocked = stuck
}
```

**Check:**
1. Don't flag missing denylist checks in Move code — Sui enforces at runtime/validator level
2. For regulated coins: check if the protocol handles the ~24hr receiving gap
3. Cross-chain bridges: verify the protocol handles the case where a recipient becomes blocked between source burn and destination mint
4. Flag any protocol that assumes denylist blocking is instant for both sending AND receiving

*Refs: [Sui DenyCapV2 docs](https://docs.sui.io/references/framework/sui_sui/coin#sui_coin_DenyCapV2),
[deny_list_v2.rs source](https://github.com/MystenLabs/sui/blob/main/crates/sui-types/src/deny_list_v2.rs)*

---

## SUI-22 — Dependency Upgrade Version Contagion

**Description:** When a Sui package upgrades, it changes its object version. The old package's version check fails for updated objects, breaking all callers of the old package. If your protocol is immutable and calls a dependency that upgrades, every call through the old package path fails permanently.

**Pattern:**
```move
// Your immutable protocol calls DEX v1 for liquidations
public fun liquidate(position: &mut Position, pool: &mut dex_v1::Pool) {
    let proceeds = dex_v1::swap(pool, position.collateral);
    // Works fine... until DEX upgrades to v2
    // DEX v2 updates all Pool objects to version=2
    // dex_v1::swap() checks version==1, fails
    // ALL liquidations permanently bricked
}
```

**The contagion effect:**
- If Protocol A is upgradeable, Protocol B using A must also be upgradeable
- Protocol C using B must be upgradeable
- One upgrade at the bottom forces every protocol above to centralize
- Choosing immutability (for security) becomes maximum vulnerability in this model

**Check:**
1. For every external dependency: is it upgradeable? Does it use object version checks?
2. If the audited protocol is immutable and any dependency is upgradeable → flag as **Critical** (protocol can be permanently bricked by a dependency upgrade)
3. If the protocol is upgradeable: does it have a mechanism to update dependency calls after upstream upgrades?
4. Check for version-gated function calls in dependencies (`assert!(obj.version == CURRENT_VERSION)`)
5. Evaluate the full dependency tree — contagion can be multi-level

*Ref: [Move is not perfect: The Upgrade Trap](https://medium.com/@gfusee33/move-is-not-perfect-2-the-upgrade-trap-1d2857417e37)*

---

## SUI-23 — Shared Object Version Check (Upgrade Safety)

**Description:** Shared objects must carry a `version: u64` field so upgraded code can
reject stale layouts. Without version gating, upgraded functions operate on objects
with old field layouts, causing deserialization failures or silent data corruption.

**Pattern:**
```move
// VULNERABLE — shared object has no version field
struct Pool has key {
    id: UID,
    balance: Balance<SUI>,
    fee_bps: u64,
}

// After upgrade adds a new field, existing Pool objects lack it
// borrow_global / dynamic access silently reads garbage or aborts

// SAFE — version-gated shared object
const CURRENT_VERSION: u64 = 1;

struct Pool has key {
    id: UID,
    version: u64,
    balance: Balance<SUI>,
    fee_bps: u64,
}

public fun swap(pool: &mut Pool, input: Coin<SUI>): Coin<USDC> {
    assert!(pool.version == CURRENT_VERSION, E_WRONG_VERSION);
    // ...
}

// Migration function bumps version after upgrade
public fun migrate_pool(pool: &mut Pool, cap: &AdminCap) {
    assert!(pool.version == CURRENT_VERSION - 1, E_ALREADY_MIGRATED);
    pool.version = CURRENT_VERSION;
}
```

**Check:**
1. Every shared object struct must have a `version: u64` field
2. Every `public` function taking `&mut SharedObj` must assert `obj.version == CURRENT_VERSION`
3. A migration function must exist to bump versions post-upgrade
4. Cross-ref: SUI-22 (dependency upgrade trap)

---

## SUI-24 — Publisher Object Not Secured

**Description:** The `Publisher` object (from `sui::package`) proves package authorship
and enables creating `Display` objects, claiming type ownership, and configuring
transfer policies. If not transferred to admin/governance in `init`, anyone with
access can spoof metadata or bypass royalties.

**Pattern:**
```move
// VULNERABLE — Publisher left as owned object, transferred to deployer without protection
fun init(otw: MY_MODULE, ctx: &mut TxContext) {
    let publisher = package::claim(otw, ctx);
    transfer::public_transfer(publisher, tx_context::sender(ctx));
    // Deployer's wallet key = single point of failure
}

// SAFE — Publisher stored in a governed wrapper or destroyed if unneeded
fun init(otw: MY_MODULE, ctx: &mut TxContext) {
    let publisher = package::claim(otw, ctx);
    // Option A: wrap in admin-gated object
    let gov = GovernedPublisher { id: object::new(ctx), publisher };
    transfer::share_object(gov);
    // Option B: if Display is already set up and Publisher isn't needed
    // package::burn_publisher(publisher);
}
```

**Check:**
1. Is `Publisher` transferred to a secure multisig/governance address?
2. If stored as owned object — is key compromise considered?
3. If `Publisher` is not needed post-init, is it burned via `package::burn_publisher`?

---

## SUI-25 — Dynamic Field Cleanup Before Object Deletion

**Description:** Dynamic fields attached to an object are NOT automatically removed
when the parent UID is deleted. Values in orphaned dynamic fields become permanently
inaccessible — causing permanent fund loss if they hold `Balance<T>` or `Coin<T>`.

**Pattern:**
```move
// VULNERABLE — deletes UID with dynamic fields still attached
public fun close_vault(vault: Vault) {
    let Vault { id, owner: _ } = vault;
    // dynamic_field holding Balance<SUI> is now orphaned forever
    object::delete(id);
}

// SAFE — remove all dynamic fields before deletion
public fun close_vault(vault: Vault): Balance<SUI> {
    let Vault { id, owner: _ } = vault;
    let balance = dynamic_field::remove<String, Balance<SUI>>(&mut id, b"funds".to_string());
    // Remove ALL other dynamic fields...
    object::delete(id);
    balance
}
```

**Check:**
1. Before any `object::delete(uid)`, verify ALL dynamic fields/objects are removed
2. If the set of dynamic field keys is unbounded, deletion may be impossible — flag as design risk
3. Check for `Balance<T>`, `Coin<T>`, or any value type with `store` in dynamic fields
4. Cross-ref: SUI-06 (dynamic field injection)

---

## SUI-26 — Kiosk Transfer Policy Bypass

**Description:** NFTs in a `Kiosk` are protected by `TransferPolicy` rules (royalties,
allowlist checks). If the `KioskOwnerCap` is not properly secured, or if `purchase`
is called without enforcing all policy rules, NFTs can be extracted without paying
royalties or passing allowlist checks.

**Pattern:**
```move
// VULNERABLE — KioskOwnerCap freely transferable, bypass via self-purchase
fun init(ctx: &mut TxContext) {
    let (kiosk, cap) = kiosk::new(ctx);
    transfer::public_share_object(kiosk);
    transfer::public_transfer(cap, tx_context::sender(ctx));
    // cap holder can list at 0 price and self-purchase, skipping royalty
}

// SAFE — cap stored securely, TransferPolicy enforced
fun init(ctx: &mut TxContext) {
    let (kiosk, cap) = kiosk::new(ctx);
    transfer::public_share_object(kiosk);
    // Store cap in governed wrapper — not directly transferable
    let gov = GovernedKiosk { id: object::new(ctx), cap };
    transfer::share_object(gov);
}
```

**Check:**
1. Is `KioskOwnerCap` stored securely (not freely transferable)?
2. Are ALL `TransferPolicy` rules enforced on every extraction path?
3. Can owner list at price 0 and self-purchase to bypass royalties?
4. Check `kiosk::list` and `kiosk::purchase` call patterns

---

## SUI-27 — UpgradeCap Lifecycle Mismanagement

**Description:** Two opposite risks: (a) `UpgradeCap` destroyed prematurely via
`sui::package::make_immutable` — makes the package permanently immutable before
critical bugs can be fixed; (b) upgrade policy is more permissive than necessary
(`compatible` when `additive_only` or `dep_only` suffices), allowing dangerous
changes to function signatures and struct layouts.

**Pattern:**
```move
// RISK A — premature immutability
fun init(ctx: &mut TxContext) {
    // Package can never be fixed if a critical bug is found
    package::make_immutable(upgrade_cap);
}

// RISK B — overly permissive upgrade policy
fun init(ctx: &mut TxContext) {
    // `compatible` allows changing function bodies + adding functions
    // Could weaken security checks in existing functions
    transfer::public_transfer(upgrade_cap, tx_context::sender(ctx));
}

// SAFE — restrict to minimum required policy, held by governance
fun init(ctx: &mut TxContext) {
    // Restrict to additive-only: can add new functions but not change existing ones
    package::only_additive_upgrades(&mut upgrade_cap);
    // Or even stricter: only dependency changes
    // package::only_dep_upgrades(&mut upgrade_cap);
    transfer::public_transfer(upgrade_cap, @governance_multisig);
}
```

**Check:**
1. Is `UpgradeCap` held by multisig/governance (not a single EOA)?
2. Is the upgrade policy the minimum required (`dep_only` > `additive_only` > `compatible`)?
3. If `make_immutable` is called — is the protocol mature enough? Are all dependencies also immutable?
4. Cross-ref: SUI-22 (immutable + upgradeable dep = bricking risk)

---

## SUI-28 — PTB Repeated Call Limit Bypass

**Description:** Sui PTBs (Programmable Transaction Blocks) allow calling the same function multiple times against the same shared object in a single atomic transaction. Per-call limits (close factors, rate limits, cooldowns) can be bypassed by calling the function N times, where each call re-reads the updated state and gets a fresh allowance.

**Pattern:**
```move
// VULNERABLE — close factor checked per-call, not per-transaction
public fun liquidate(market: &mut Market, obligation_id: ID, repay_amount: u64) {
    let debt = market.obligation(obligation_id).debt();
    let max_repay = debt * close_factor; // recalculated on CURRENT debt
    assert!(repay_amount <= max_repay, E_CLOSE_FACTOR_EXCEEDED);
    // ... execute liquidation, reduce debt ...
}
// Attacker calls liquidate() 5x in one PTB: each call gets 50% of REMAINING debt
// Total: 50% + 25% + 12.5% + 6.25% + 3.125% = 96.875% liquidated
```

**Risk:** Any per-call numeric limit becomes meaningless if the function can be called repeatedly in the same PTB with state persisting between calls. This is unique to Sui's PTB model — on EVM, each tx is independent.

**Check:**
1. For every function with a per-call numeric limit (close factor, max withdrawal, rate limit), verify the limit is tracked per-TRANSACTION, not per-call
2. Look for patterns where: (a) a limit is checked against current state, (b) state is modified to reduce the denominator, (c) no flag prevents re-invocation in the same PTB
3. Common vulnerable patterns: liquidation close factors, withdrawal rate limits, flash loan stacking across different assets, reward claim limits
4. Fix patterns: (a) store original state in a hot-potato that persists across calls, (b) set a per-obligation/per-asset flag that prevents repeated operations, (c) track cumulative amounts via a transaction-scoped accumulator

**Real-World Example:** CurrentSUI lending protocol — close factor of 50% bypassed via 3 liquidation calls in one PTB, achieving 87.5% total liquidation. Position pushed from recoverable to bad debt.

---

## SUI-29 — Time-Lock Window State Guarantees

**Description:** Delayed/time-locked transfer wrappers where the observation window does not guarantee state immutability or binding commitment. Two distinct sub-patterns:

**A) Mutation during delay window:**
The wrapper owner can `borrow_mut` and modify the inner object while a transfer is pending. The new owner receives a different object than what was visible when the transfer was scheduled.

```move
// INFORMATIONAL — owner can mutate inner object during pending transfer
public fun borrow_mut<T: key + store>(self: &mut DelayedWrapper<T>): &mut T {
    // No check whether a transfer is pending — owner can change inner state
    &mut self.obj
}

// SAFER — restrict mutation during active transfer
public fun borrow_mut<T: key + store>(self: &mut DelayedWrapper<T>): &mut T {
    assert!(!self.transfer_pending, EMutationDuringTransfer);
    &mut self.obj
}
```

**B) Cancellation after deadline:**
The owner can `cancel_schedule` even after the delay has fully elapsed, as long as `execute_transfer` hasn't been called. The delay provides observation time but not a binding commitment — observers cannot rely on the transfer completing.

```move
// INFORMATIONAL — cancel works even after deadline passed
public fun cancel_schedule<T: key + store>(self: &mut DelayedWrapper<T>) {
    // No check: clock::timestamp_ms(clock) < self.deadline
    self.transfer_pending = false;
    self.new_owner = @0x0;
}
```

**Check:**
1. Does the delay wrapper allow mutable access to the inner object during a pending transfer/unwrap? If yes, flag as Informational
2. Can a scheduled operation be cancelled after the deadline passes? If yes, flag as Informational — the delay is observation-only
3. Check if this behavior is documented — if documented, keep at Info; if not, upgrade to Low

**Severity guidance:** Both patterns are often intentional design choices (owner retains full custody until transfer executes). Do NOT classify above Low unless there is no documentation and downstream protocols depend on the commitment guarantee.

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
- [ ] Objects used for pricing/permissions validated by UID against registry (SUI-18)
- [ ] No unconditional `balance::destroy_zero()` — check value > 0 first (SUI-19)
- [ ] Flash loan receipts validated against originating pool before repayment (SUI-20)
- [ ] No false-positive denylist findings — enforcement is validator-level, not Move code; check epoch gap for receiving (SUI-21)
- [ ] All external dependencies checked for upgradeability — immutable protocol + upgradeable dep = bricking risk (SUI-22)
- [ ] All shared objects have `version: u64` field; all public functions assert version (SUI-23)
- [ ] `Publisher` object transferred to governance or burned post-init (SUI-24)
- [ ] All dynamic fields removed before `object::delete(uid)` — no orphaned balances (SUI-25)
- [ ] `KioskOwnerCap` stored securely; `TransferPolicy` rules enforced on every extraction (SUI-26)
- [ ] `UpgradeCap` held by governance with minimum-required policy; premature immutability flagged (SUI-27)
- [ ] Per-call numeric limits (close factor, rate limits, cooldowns) enforced per-TRANSACTION not per-call — PTB repeated call bypass (SUI-28)
- [ ] Time-lock wrappers: check if inner object mutable during pending transfer, and if cancel works after deadline (SUI-29)
