# Common Move Security Patterns

Chain-agnostic security checks that apply to all Move code, regardless of whether
it targets Sui or Aptos. Run these on every audit before loading chain-specific patterns.

---

## 1. Access Control

### 1.1 Missing Signer/Capability Validation
**Pattern:** `public entry fun` with no `&signer` parameter and no capability check.
**Risk:** Anyone can call the function.
**Check:** Every state-mutating entry function must either:
- Accept a `&signer` and validate it against a stored admin/owner address, OR
- Accept a capability object that is unforgeable (no `copy` ability)

```move
// VULNERABLE — no access control
public entry fun set_fee(new_fee: u64) {
    borrow_global_mut<Config>(@admin).fee = new_fee;
}

// SAFE — capability gating
public entry fun set_fee(cap: &AdminCap, new_fee: u64) {
    borrow_global_mut<Config>(@admin).fee = new_fee;
}
```

### 1.2 Overly Broad Capability Abilities
**Pattern:** Capability struct has `copy` or `store` ability.
**Risk:** Capabilities can be duplicated or stored arbitrarily, defeating the access model.
**Check:** Administrative capability structs should have zero or only `drop` ability.

```move
// VULNERABLE
struct AdminCap has copy, store, drop {}

// SAFE
struct AdminCap has drop {}
```

### 1.3 Hardcoded Address Checks
**Pattern:** `assert!(signer::address_of(account) == @0x1234, E_NOT_ADMIN)`
**Risk:** Admin address is immutable; if key is lost, the protocol is bricked. No upgrade path.
**Check:** Flag hardcoded address checks. Prefer capability-based patterns.

### 1.4 Two-Step Ownership Transfer Missing
**Pattern:** Ownership transferred in a single step without confirmation.
**Risk:** Typo in address permanently locks the protocol.
**Check:** Critical ownership transfers should use a pending → accept pattern.

### 1.5 API Naming Consistency (Misleading Conversion Functions)
**Pattern:** `into_X` / `from_X` conversion functions that don't actually perform conversion — they're raw wrappers that just reinterpret the value without scaling, type conversion, or validation.
**Risk:** Integrators assume the function performs real conversion (e.g., `into_UD30x9` implies scaling to 30-digit-9-decimal fixed-point), but it's just a struct wrap. Downstream math is silently wrong.
**Check:** For every `into_*` / `from_*` / `to_*` function, verify the function body matches what the name implies. Misleading names are Low/Informational.

### 1.6 Authorization Returns Bool Without Assertion
**Pattern:** Authorization function returns `bool` instead of aborting on failure. Callers can silently discard the return value, bypassing the check entirely.
**Risk:** If a caller writes `is_authorized(registry, addr);` instead of `assert!(is_authorized(registry, addr), E_NOT_AUTHORIZED)`, the authorization check runs but the result is ignored — access is granted unconditionally.

```move
// VULNERABLE — returns bool, caller can ignore the result
public fun is_authorized(registry: &Registry, addr: address): bool {
    registry.admins.contains(&addr)
}

// Caller forgets to check return value — authorization silently bypassed
public entry fun admin_action(registry: &Registry, ctx: &TxContext) {
    is_authorized(registry, tx_context::sender(ctx)); // return value discarded!
    do_critical_operation();
}

// SAFE — aborts on failure, cannot be silently ignored
public fun assert_authorized(registry: &Registry, addr: address) {
    assert!(registry.admins.contains(&addr), ENotAuthorized);
}
```

**Check:**
1. Grep for authorization/permission functions that return `bool` (names like `is_admin`, `is_authorized`, `has_role`, `check_permission`)
2. Trace every call site — is the return value used in an `assert!` or `if` check?
3. If ANY call site discards the return value → flag as High
4. Recommend converting to `assert_*` pattern that aborts on failure

---

## 2. Arithmetic & Overflow

### 2.1 Unchecked Integer Arithmetic
**Pattern:** Addition, subtraction, multiplication without overflow/underflow checks.
**Risk:** In Move, integer overflow **aborts** by default — but subtraction underflow on `u64` is a runtime abort that can be used as a DoS.
**Check:** Verify that arithmetic paths can't be forced into abort by a malicious caller.

```move
// POTENTIAL DOS — attacker supplies balance = 0
let result = balance - fee; // aborts if fee > balance
```

### 2.2 Division Before Multiplication (Precision Loss)
**Pattern:** `(a / b) * c` instead of `(a * c) / b`
**Risk:** Integer division truncation causes systematic precision loss, exploitable in DeFi.
**Check:** In any fee/interest/share calculation, verify multiplication happens before division.

### 2.3 Division by Zero
**Pattern:** Division where denominator can be zero.
**Risk:** Runtime abort (DoS).
**Check:** All divisions must assert denominator != 0.

### 2.4 Cast Truncation
**Pattern:** Casting from larger to smaller integer type (e.g., `u128` → `u64`).
**Risk:** Silent truncation of high bits.
**Check:** All narrowing casts should have bounds assertions.

### 2.5 Bit-Shift Wrapping (Silent Overflow)
**Pattern:** Bit-shift operations (`<<`, `>>`) in custom math or fixed-point libraries.
**Risk:** Unlike standard arithmetic (`+`, `-`, `*`), **bit-shifts in Move do NOT abort on overflow — they silently wrap**. `(1u64 << 64)` produces `0`, not an abort. `(x as u256) << 64` wraps around if the result exceeds `MAX_U256`. This makes custom overflow checks for bit-shifts critical — an off-by-one in the boundary condition (`<` vs `>=`) silently produces a corrupted result instead of aborting.
**Check:**
1. Grep for `<<`, `>>`, `shl`, `shr`, `checked_shl`, `checked_shr` in math/utility modules
2. For each shift: is the operand validated against bit-width overflow BEFORE the shift?
3. What is the exact boundary condition? Verify the comparison operator (`<` vs `<=` vs `>=`)
4. If the shift result feeds into balance, liquidity, supply, or share calculations → Critical

```move
// VULNERABLE — boundary check uses < instead of >=, allows value at exact boundary
fun checked_shl(n: u256, shift: u8): u256 {
    assert!(n < (1u256 << (256 - (shift as u16))), E_OVERFLOW); // off-by-one: n == boundary passes
    n << shift  // silently wraps to small number
}

// SAFE — correct boundary
fun checked_shl(n: u256, shift: u8): u256 {
    assert!(n <= (MAX_U256 >> (shift as u16)), E_OVERFLOW);  // tight bound
    n << shift
}
```

### 2.6 Fixed-Point Helper Library Overflow (Multiply-Before-Divide)

**Pattern:** Protocol uses a fixed-point math library (e.g., `float.move`, `decimal.move`, `wad_ray.move`) whose `mul` function computes `(a.value * b.value) / WAD` internally. The intermediate product `a.value * b.value` can overflow and abort **before** the normalizing division executes. When the caller does `A.mul(B).div(C)`, the overflow in `mul` fires before `div(C)` can reduce the result to a safe range.

**Risk:** If the abort occurs inside a periodic accounting update (reward accumulator, interest accrual, index refresh) and the state checkpoint (`last_update_time`, `cumulative_index`) is written **after** the overflowing line, the state never advances. Every future call hits the same overflow with an ever-growing time delta — **permanent, irrecoverable protocol deadlock**.

**Why this is different from 2.2:** Section 2.2 checks expression-level multiply-before-divide for precision loss. This check targets **hidden overflow inside helper library internals** that the calling module cannot see. The calling code looks safe (`from(x).mul(from(y)).div(from(z))`) but the helper's internal representation and bounds enforcement create an overflow that fires before the division.

```move
// VULNERABLE — overflow hidden inside float::mul
// float::mul does: (a.value * b.value) / WAD, then asserts result <= VALUE_MAX
// If total_rewards * time_passed_ms > U64_MAX, the mul aborts before div executes
let unlocked_rewards =
    float::from(pool_reward.total_rewards)
        .mul(float::from(time_passed_ms))       // <-- OVERFLOW HERE
        .div(float::from(duration));             // never reached

// SAFE — divide first, then multiply (intermediate stays small)
let unlocked_rewards =
    float::from(pool_reward.total_rewards)
        .div(float::from(duration))              // total_rewards / duration <= total_rewards
        .mul(float::from(time_passed_ms));       // result * time_passed <= total_rewards
```

**Check:**
1. Identify ALL fixed-point/decimal helper modules used by the target protocol (`float`, `decimal`, `wad_ray`, `fixed_point32`, `fixed_point64`, `math`)
2. **Open each helper module.** Read `mul`, `div`, `from`, `floor`, `ceil`. Derive:
   - Internal representation (e.g., `value * WAD` where WAD = 1e18)
   - Intermediate expression in `mul` (e.g., `a.value * b.value / WAD`)
   - Maximum allowed value (e.g., `VALUE_MAX = U64_MAX * WAD`)
   - Whether overflow check fires before or after the normalizing division
3. For every call site of the form `A.mul(B).div(C)` or `A * B / C` using helpers:
   - Derive: can `A * B` (in raw scaled representation) exceed the helper's max before `/ C` executes?
   - Derive concrete bounds: what values of A and B trigger overflow?
   - Use production-realistic values (token decimals, time in ms, reward amounts)
4. If overflow is reachable, check whether it occurs **before a state checkpoint** (see 12.1)
5. Cross-ref: 12.1, DEFI-85, DEFI-86

### 2.5 Bitwise Operations — No Overflow Protection

**Pattern:** Move auto-aborts on arithmetic overflow (addition, subtraction, multiplication), but bitwise operations (`<<`, `>>`, `&`, `|`, `^`) have **no such safeguards**. Bit shifts can silently overflow or produce unexpected results.

```move
// VULNERABLE — left shift can silently lose high bits
let shifted = value << amount;  // no overflow abort like arithmetic ops

// SAFE — guard shift amount and check for overflow
assert!(amount < 64, E_SHIFT_OVERFLOW);
assert!(value <= (MAX_U64 >> amount), E_WOULD_OVERFLOW);
let shifted = value << amount;
```

**Check:**
1. Grep all bitwise operations (`<<`, `>>`, `&`, `|`, `^`) in the codebase
2. For each left shift: can the shift amount exceed the bit width? Can high bits be lost?
3. For each right shift: is precision loss acceptable?
4. Especially dangerous in fee calculations, fixed-point math, and bitmap/flag manipulation

### 2.7 Delayed Overflow via Immutable Construction Parameters

**Pattern:** A struct field is set at construction time (e.g., `wrap`, `new`, `init`) and never validated for upper bounds. Later, the field is combined with a runtime value (e.g., `clock::timestamp_ms() + self.delay`) in arithmetic that can overflow `u64`.

**Risk:** Since Move uses checked arithmetic (abort, not wrap), the overflow permanently bricks the function. If the field is immutable (no setter, no admin rescue), the object is permanently locked with no recovery path. This is distinct from 2.6 (library-internal overflow) — here the overflow is in application-level arithmetic between a stored param and a runtime value.

```move
// VULNERABLE — no upper bound on delay, permanently locks object if near u64::MAX
public fun wrap<T: key + store>(obj: T, min_delay_ms: u64, ctx: &mut TxContext): DelayedWrapper<T> {
    // min_delay_ms stored as-is, no validation
    DelayedWrapper { id: object::new(ctx), obj, min_delay_ms }
}

public fun schedule<T: key + store>(self: &mut DelayedWrapper<T>, clock: &Clock) {
    let deadline = clock::timestamp_ms(clock) + self.min_delay_ms; // overflows → abort forever
    self.deadline = deadline;
}

// SAFE — bounded at construction
const MAX_DELAY_MS: u64 = 365 * 24 * 60 * 60 * 1000; // 1 year

public fun wrap<T: key + store>(obj: T, min_delay_ms: u64, ctx: &mut TxContext): DelayedWrapper<T> {
    assert!(min_delay_ms <= MAX_DELAY_MS, ETooLong);
    DelayedWrapper { id: object::new(ctx), obj, min_delay_ms }
}
```

**Check:**
1. Find all struct fields set at construction/`wrap`/`new` time with no upper-bound validation
2. Trace each field to where it's used in arithmetic with runtime values (`clock`, `epoch`, counters)
3. If `immutable_field + clock::timestamp_ms()` can overflow `u64`, flag it
4. Verify a recovery path exists (unwrap, admin rescue, timeout fallback)
5. Also check: missing public accessors for construction parameters — downstream protocols cannot programmatically validate the configured value

---

## 3. Resource Safety

### 3.1 Resource Leak
**Pattern:** A resource is created but never moved to storage or dropped.
**Risk:** Move's type system prevents this at compile time — but check for structs without `drop` that might be accidentally destructured.
**Check:** All `key`-ability structs must end up in global storage. If a function creates a resource, trace where it goes.

### 3.2 Unauthorized Resource Extraction
**Pattern:** `move_from<T>(addr)` without verifying the caller owns that address.
**Risk:** Theft of stored resources.
**Check:** Every `move_from` must be preceded by an ownership/capability check.

```move
// VULNERABLE
public entry fun withdraw(account: &signer, target: address) {
    let coin = move_from<CoinStore>(target); // no ownership check!
    // ...
}
```

### 3.3 Borrow After Move
**Pattern:** Using a reference to a value after it has been moved.
**Risk:** Caught by the type system, but watch for patterns that try to work around it.

### 3.4 Double Spend via Phantom Resources
**Pattern:** Protocol tracks balances off-chain or in a separate table while actual assets flow differently.
**Risk:** Inconsistency between accounting and actual assets.
**Check:** For every credit to internal accounting, verify there is a corresponding on-chain asset transfer.

---

## 4. Logic & Invariant Violations

### 4.1 Missing Invariant Assertions
**Pattern:** Protocol has documented invariants (e.g., "total supply == sum of all balances") with no on-chain enforcement.
**Risk:** Invariants can drift due to edge cases, creating exploitable inconsistencies.
**Check:** Critical invariants should be checked with `assert!` at the end of state-mutating functions, especially during development/testing.

### 4.2 Incorrect Comparison Operators
**Pattern:** `>` vs `>=`, `<` vs `<=` in boundary checks.
**Risk:** Off-by-one exploits in withdrawal limits, stake amounts, etc.
**Check:** Every boundary condition — pay extra attention to fee calculations, minimum deposits, maximum withdrawals.

### 4.3 State Machine Violations
**Pattern:** State enum transitions without exhaustive checks.
**Risk:** Skipping states or transitioning to invalid states.
**Check:** Map all state machine transitions. Verify each is gated and exhaustive.

### 4.4 Timestamp/Epoch Manipulation
**Pattern:** Logic that depends on `Clock` (Sui) or `timestamp::now_seconds` (Aptos).
**Risk:** Validators have limited but real ability to influence block timestamps. Flash-loan window exploits.
**Check:** Avoid hardcoded time windows shorter than ~30 seconds. Flag any logic where timestamp manipulation gives economic benefit.

### 4.5 Inverted Security Logic
**Pattern:** A security check that blocks the wrong party, compares the wrong direction, or asserts the opposite of the intended condition. The check exists but protects the attacker instead of the protocol.
**Risk:** The presence of the check creates a false sense of security — code reviewers see an `assert!` and move on, but the logic is backwards.

```move
// VULNERABLE — checks recipient (to) instead of sender (from) for liquidate-only restriction
fun assert_not_liquidate_only<T>(registry: &InvestorInfo<T>, to: &PartyInfo) {
    assert!(!lock_manager::is_liquidate_only(registry, *to.id()), ELiquidateOnly);
    // BUG: should check the sender, not the recipient
}

// VULNERABLE — inverted time comparison, lock expires immediately
fun assert_lock_active(lock: &Lock, clock: &Clock) {
    assert!(clock::timestamp_ms(clock) > lock.expires_at, ELockActive);
    // BUG: should be < (lock is active while time is BEFORE expiry)
}

// SAFE — correct party and correct direction
fun assert_not_liquidate_only<T>(registry: &InvestorInfo<T>, from: &PartyInfo) {
    assert!(!lock_manager::is_liquidate_only(registry, *from.id()), ELiquidateOnly);
}
fun assert_lock_active(lock: &Lock, clock: &Clock) {
    assert!(clock::timestamp_ms(clock) < lock.expires_at, ELockActive);
}
```

**Check:**
1. For every `assert!` in authorization/security context: does the variable being checked match the intended party (sender vs recipient, from vs to)?
2. For every comparison operator in time/deadline checks: does `<` vs `>` match the intended semantics?
3. For every boolean negation (`!`): trace the logic — is the condition checking what the error message claims?
4. Cross-ref with error constant names — does the error name match what the condition actually prevents?

### 4.6 Wrong Field Update
**Pattern:** A function intended to update field X accidentally reads or writes to field Y. Both fields have the same type (`u64`, `u128`, `address`), so the compiler doesn't catch it.
**Risk:** Silent data corruption — the intended field is unchanged, a different field is overwritten. Can lead to authorization bypass if an admin field is overwritten, or fund loss if a balance field is corrupted.

```move
// VULNERABLE — function is called set_fee but updates balance
public fun set_fee(config: &mut Config, new_fee: u64) {
    config.balance = new_fee;  // BUG: should be config.fee = new_fee
}

// VULNERABLE — reads wrong field for comparison
public fun check_limit(pool: &Pool, amount: u64) {
    assert!(amount <= pool.min_deposit, E_EXCEEDS_LIMIT);
    // BUG: should compare against pool.max_withdrawal
}

// SAFE — correct fields
public fun set_fee(config: &mut Config, new_fee: u64) {
    config.fee = new_fee;
}
```

**Check:**
1. For every `set_*` / `update_*` function, verify the field being written matches the function name and parameter name
2. For every comparison in validation logic, verify the field being compared is the one relevant to the check (e.g., `max_withdrawal` for withdrawal limits, not `min_deposit`)
3. Pay special attention to structs with multiple same-typed fields (`u64`, `address`) — compiler cannot catch field swaps
4. Cross-ref: field names in events should match the fields that were actually modified

---

## 5. Input Validation

### 5.1 Missing Zero-Value Checks
**Pattern:** Functions that accept `amount: u64` without asserting `amount > 0`.
**Risk:** Zero-value operations that corrupt state, skip logic, or trigger division-by-zero downstream.

### 5.2 Missing Address Validation
**Pattern:** Functions that accept `address` parameters without validating they are non-zero or known.
**Risk:** Sending to zero address, interacting with uninitialized modules.

### 5.3 Length/Bounds Checks on Vectors
**Pattern:** Accessing `vector<T>` by index without bounds checking.
**Risk:** Runtime abort (DoS) if index is out of bounds.
**Check:** All vector index operations should be bounds-checked or use safe access patterns.

---

## 6. Cross-Module & External Call Safety

### 6.1 Reentrancy via Cross-Module Calls
**Pattern:** Calling an external module function while holding mutable borrows or mid-state-update.
**Risk:** Move doesn't have EVM-style reentrancy, but cross-module calls while in inconsistent state can still be exploited.
**Check:** Ensure state is in a consistent, valid state before any external call. Update state after, not before external calls (checks-effects-interactions pattern).

### 6.2 Unvalidated Return Values
**Pattern:** Return values from external module calls used without validation.
**Risk:** External module could return unexpected values.
**Check:** Validate all values returned from external calls before using them in critical logic.

### 6.3 Dependency on Upgradeable Modules
**Pattern:** Protocol depends on an external module that can be upgraded.
**Risk:** Upgrade changes behavior, breaking assumptions.
**Check:** Flag all external module dependencies. Note which are upgradeable.

### 6.4 Stale State from Hidden External Mutations

**Pattern:** Protocol reads a value (exchange rate, price, index), then calls an external module that internally mutates that same value (e.g., interest accrual), making the previously-read value stale.

```move
// VULNERABLE — reads exchange rate, then calls withdraw() which accrues interest internally
public fun user_withdraw(vault: &mut Vault, pool: &mut ExternalPool, shares: u64, ctx: &mut TxContext) {
    let rate = get_exchange_rate(pool);         // reads rate BEFORE accrual
    let amount = shares * rate / PRECISION;     // calculates with stale rate
    external_pool::withdraw(pool, amount);      // this internally calls accrue_interest()!
    // User underpaid — rate was stale, vault accounting silently drifts
}

// SAFE — accrue first, then read, or re-read after external call
public fun user_withdraw(vault: &mut Vault, pool: &mut ExternalPool, shares: u64, ctx: &mut TxContext) {
    external_pool::accrue_interest(pool);       // force accrual first
    let rate = get_exchange_rate(pool);         // now rate is fresh
    let amount = shares * rate / PRECISION;
    external_pool::withdraw(pool, amount);
}
```

**Check:**
1. For every external call: does the called function internally mutate state that you already read?
2. Common in yield vaults, lending wrappers, and aggregators built on top of other protocols
3. Look for `get_*` / `calculate_*` calls followed by an external `deposit` / `withdraw` / `swap`
4. Re-read or re-derive values after any external call that may have side effects

---

## 7. Upgradeability & Admin Risks

### 7.1 Unconstrained Upgrade Authority
**Pattern:** Single key controls upgrades with no timelock or multisig.
**Risk:** Compromised key = full protocol takeover.
**Check:** Upgrade authority should be governed. Flag single-key upgrade authority as Medium/High depending on TVL.

### 7.2 Initialization Functions Callable Multiple Times
**Pattern:** `init` or `initialize` function that can be called by anyone after deployment.
**Risk:** Reinitialization overwrites config, disables the protocol, or escalates privileges.
**Check:** Initialization must be one-time-only, enforced on-chain.

```move
// VULNERABLE — anyone can reinitialize
public entry fun initialize(admin: &signer, config: Config) {
    move_to(admin, config);
}

// SAFE — aborts if already initialized
public entry fun initialize(admin: &signer, config: Config) {
    assert!(!exists<Config>(signer::address_of(admin)), E_ALREADY_INITIALIZED);
    move_to(admin, config);
}
```

### 7.3 Emergency Pause Missing
**Pattern:** No circuit breaker / pause mechanism.
**Risk:** In an active exploit, there's no way to halt the protocol.
**Check:** Note absence of pause mechanism. Not a vulnerability itself, but an operational risk worth flagging as Info.

### 7.4 Incomplete Pause Coverage
**Pattern:** Pause flag exists but is not checked on ALL public/entry functions.
**Risk:** Attacker routes through an unpaused code path while the protocol believes it's halted.

```move
// VULNERABLE — pause checked on deposit but not on withdraw
public entry fun deposit(state: &State, amount: u64) {
    assert!(!state.paused, E_PAUSED); // checked here
}
public entry fun withdraw(state: &State, amount: u64) {
    // Missing pause check — attacker withdraws during "pause"
}

// SAFE — every state-mutating function checks pause
public entry fun withdraw(state: &State, amount: u64) {
    assert!(!state.paused, E_PAUSED);
    // ... withdrawal logic
}
```

**Check:** Grep `paused` or `is_paused`. List every public/entry function. Verify EACH one checks the pause flag. Admin emergency functions may intentionally bypass pause.

### 7.5 Unpinned Dependencies in Move.toml
**Pattern:** Git dependencies in `Move.toml` without pinned `rev` or `tag`.
**Risk:** Dependency can change silently — supply chain attack imports malicious code or breaking changes.

```toml
# VULNERABLE — unpinned, tracks latest commit on main
[dependencies]
SomeProtocol = { git = "https://github.com/example/protocol.git", subdir = "contracts" }

# SAFE — pinned to specific commit
[dependencies]
SomeProtocol = { git = "https://github.com/example/protocol.git", subdir = "contracts", rev = "abc123def" }
```

**Check:** Open `Move.toml`. Every git dependency must have `rev = "..."` or `tag = "..."`. Flag unpinned deps as Medium (supply chain risk).

---

## 8. Type Safety & Value Validation

### 8.1 Generic Type Parameter Not Validated

**Pattern:** Functions accepting generic `<T>` without verifying `T` matches the stored/expected type.

**Risk:** Attackers deposit worthless tokens, repay with wrong assets, or drain pools by type confusion.
This is the **#1 Critical pattern** across real Move audits.

```move
// VULNERABLE — accepts any CoinType for repayment
public fun repay_flash_loan<T>(
    pool: &mut Pool,
    coin: Coin<T>,
    receipt: FlashReceipt,
) {
    // No check that T matches the originally borrowed coin type!
    balance::join(&mut pool.balance, coin::into_balance(coin));
    let FlashReceipt { amount: _ } = receipt;
}

// SAFE — type parameter bound to pool and receipt
public fun repay_flash_loan<T>(
    pool: &mut Pool<T>,
    coin: Coin<T>,
    receipt: FlashReceipt<T>,
) {
    balance::join(&mut pool.balance, coin::into_balance(coin));
    let FlashReceipt { amount: _ } = receipt;
}
```

**Check:**
1. Every function with a generic type parameter — how is the type validated?
2. Flash loan repayment: does the receipt bind the type to the original loan?
3. Lending functions: is `CoinType` verified against the reserve/pool it belongs to?
4. Cross-check: does the protocol store the expected type and compare at runtime?

*Real audit refs: Navi (all lending functions lack CoinType validation — Critical),
Econia (place_market_order no type check — Critical)*

*See also: APT-03 (Aptos coin type whitelisting), SUI-20 (Sui flash loan receipt pool validation)*

### 8.2 Return Values in Wrong Order

**Pattern:** Functions returning multiple values in incorrect order, silently corrupting all callers.

```move
// VULNERABLE — returns (reserve_y, reserve_x) instead of (reserve_x, reserve_y)
public fun get_reserves<X, Y>(pool: &Pool<X, Y>): (u64, u64) {
    (pool.reserve_y, pool.reserve_x)  // swapped!
}
```

**Check:** Verify all multi-return functions return values in the documented/expected order.
Cross-reference every call site — a swap here corrupts all swap calculations downstream.

*Real audit ref: KriyaDEX (get_reserves wrong order — High)*

### 8.3 Self-Referential Validation (Always-True Checks)

**Pattern:** Security checks that compare a value against itself or use tautological conditions.

```move
// VULNERABLE — compares version against itself, always passes
public fun check_version(config: &Config) {
    assert!(config.version == config.version, E_WRONG_VERSION);
}

// VULNERABLE — inverted existence check
public fun remove_authorized_user(list: &mut vector<address>, user: address) {
    assert!(!vector::contains(list, &user), E_NOT_FOUND);  // should be WITHOUT the !
}

// SAFE
public fun check_version(config: &Config) {
    assert!(config.version == CURRENT_VERSION, E_WRONG_VERSION);
}
```

**Check:**
1. Search for `assert!` conditions where both sides reference the same variable
2. Check for inverted boolean logic (`!exists` vs `exists`, `!contains` vs `contains`)
3. Verify all security-critical comparisons use an independent reference value

*Real audit refs: Hop Aggregator (version self-comparison — High),
Typus Finance (inverted existence check — High)*

### 8.4 Constant Definition Errors

**Pattern:** Hardcoded constants with wrong values — silently breaks security assumptions.

```move
// REAL BUGS FROM AUDITS
const MAX_U64: u64 = 0xFFFFFFFFFFFFFFF;              // 15 hex digits, should be 16
const DAY_SECONDS: u64 = 600;                          // 10 minutes, not 24 hours!
const ONE_DAY: u64 = 0;                                // should be 86_400_000
const SECONDS_PER_YEAR: u64 = 365 * 24 * 60 * 60 * 1000; // 1000x too large (ms not s)

// CORRECT
const MAX_U64: u64 = 0xFFFFFFFFFFFFFFFF;               // 16 hex digits
const DAY_SECONDS: u64 = 86_400;                        // 24 * 60 * 60
const ONE_DAY_MS: u64 = 86_400_000;                     // 24 * 60 * 60 * 1000
const SECONDS_PER_YEAR: u64 = 31_536_000;               // 365 * 24 * 60 * 60
```

**Check:**
1. Grep all `const` definitions — verify values match names and documentation
2. Check MAX_U64/MAX_U128 have correct number of hex digits
3. Verify time constants: `86400` (day), `31536000` (year), `3600` (hour)
4. Check precision/scaling constants match token decimals

*Real audit refs: Bluefin (MAX_u64 missing digit — Critical),
Dexlyn (DAY_SECONDS=600 — High), SuiPad (one_day=0 — High),
Navi (SECONDS_PER_YEAR 1000x — Critical)*

---

## 9. State Consistency

### 9.1 Missing State Update After Claim/Refund/Withdraw

**Pattern:** Function transfers assets but doesn't flip a "claimed" flag or decrement balance.
Users call repeatedly to drain the protocol.

```move
// VULNERABLE — no state update after refund
public entry fun claim_refund(
    vault: &mut Vault,
    cert: &Certificate,
    ctx: &mut TxContext
) {
    let refund = coin::take(&mut vault.balance, cert.invested_amount, ctx);
    transfer::public_transfer(refund, tx_context::sender(ctx));
    // BUG: cert.claimed never set to true — user calls again to drain
}

// SAFE — mark as claimed
public entry fun claim_refund(
    vault: &mut Vault,
    cert: &mut Certificate,
    ctx: &mut TxContext
) {
    assert!(!cert.claimed, E_ALREADY_CLAIMED);
    cert.claimed = true;
    let refund = coin::take(&mut vault.balance, cert.invested_amount, ctx);
    transfer::public_transfer(refund, tx_context::sender(ctx));
}
```

**Check:**
1. Every claim/refund/withdraw function — is there a flag or balance update preventing re-invocation?
2. Search for transfer/send calls — does the function modify state to reflect the transfer?
3. Check if the receipt/certificate/ticket is consumed (destroyed) or just read

*Real audit refs: SuiPad (claim_refund no state update — Critical),
MoveGPT (refund_entry callable multiple times — High),
Mysten Republic (repeated invocation for excessive claims — High)*

### 9.2 Double Scaling / Unit Mixing

**Pattern:** Scaled balances (with interest index) mixed with raw amounts in the same calculation.

```move
// VULNERABLE — comparing scaled debt with unscaled repayment
let scaled_debt = user.scaled_variable_debt;    // in RAY units (1e27)
let repay_amount = coin::value(&payment);       // in token decimals (1e6 for USDC)
assert!(repay_amount >= scaled_debt, E_UNDERPAY); // apples vs oranges!

// SAFE — normalize to same scale
let actual_debt = scaled_debt * borrow_index / RAY;
assert!(repay_amount >= actual_debt, E_UNDERPAY);
```

**Check:**
1. Identify all "scaled" or "indexed" values in the codebase
2. Every arithmetic operation must use values in the same scale
3. Watch for variables named `scaled_*` used directly with raw amounts
4. Check interest index: multiply or divide? Verify direction matches the math

*Real audit refs: Navi (scaled supply used with unscaled amounts — Critical),
AAVE v3 (borrow index set to token decimals not RAY — High),
ThalaSwapV2 (double-upscaling in pay_flashloan — Critical)*

### 9.3 Missing Recovery / Withdrawal Functions

**Pattern:** Tokens or fees accumulate in a contract with no function to extract them.

**Check:**
1. For every fee collection (`balance::join`, `coin::put`): does a corresponding withdrawal function exist?
2. For every vault/pool: can residual tokens be recovered by admin?
3. Check refund flows: can unused tokens in failed campaigns/auctions be recovered?
4. If missing: severity is High (permanent fund lock)

*Real audit refs: Kofi Finance (deposit fees, no withdraw — Critical),
Scallop (flash loan fees trapped — High),
SuiPad (unused tokens stuck in vault — High)*

### 9.4 Self-Transfer Snapshot Manipulation
**Pattern:** User transfers tokens to themselves, triggering fee/reward snapshot updates without real economic activity.
**Risk:** If fee collection or reward distribution logic fires on every transfer (including self-transfers), an attacker can manipulate accumulators, claim unearned rewards, or force fee distributions.

```move
// VULNERABLE — transfer triggers reward snapshot, no self-transfer check
public fun transfer(pool: &mut Pool, from: address, to: address, amount: u64) {
    update_reward_snapshot(pool, from);  // triggers on self-transfer too
    update_reward_snapshot(pool, to);
    move_tokens(pool, from, to, amount);
}

// SAFE — block self-transfers or skip snapshot on self-transfer
public fun transfer(pool: &mut Pool, from: address, to: address, amount: u64) {
    assert!(from != to, E_SELF_TRANSFER);
    update_reward_snapshot(pool, from);
    update_reward_snapshot(pool, to);
    move_tokens(pool, from, to, amount);
}
```

**Check:** Search for transfer/send functions. Does `from == to` trigger any side effects (rewards, fees, snapshots)?

### 9.5 Round-Trip Profitability
**Pattern:** `deposit(X)` followed by immediate `withdraw(all)` returns more than X.
**Risk:** Rounding asymmetry, fee accounting gaps, or share calculation bugs allow value extraction through repeated deposit/withdraw cycles.

```move
// VULNERABLE — deposit rounds UP shares, withdraw rounds UP tokens
public fun deposit(pool: &mut Pool, amount: u64): u64 {
    let shares = (amount * pool.total_shares + pool.total_assets - 1) / pool.total_assets; // rounds UP
    pool.total_shares = pool.total_shares + shares;
    shares
}
public fun withdraw(pool: &mut Pool, shares: u64): u64 {
    let amount = (shares * pool.total_assets + pool.total_shares - 1) / pool.total_shares; // rounds UP
    pool.total_shares = pool.total_shares - shares;
    amount // user gets MORE than deposited
}

// SAFE — deposit rounds DOWN (fewer shares), withdraw rounds DOWN (fewer tokens)
```

**Check:** Invariant: `withdraw(deposit(X)) <= X` must always hold. Deposit should round DOWN (protocol keeps dust), withdraw should round DOWN (protocol keeps dust). Cross-ref: DEFI-39

---

## 10. Control Flow & Protocol Logic

### 10.1 Recursive / Circular Function Calls

**Pattern:** Function A calls function B which calls A again — infinite recursion, permanent DoS.

```move
// VULNERABLE — circular call chain
public fun distribute_fees<X, Y>(pool: &mut Pool<X, Y>) {
    let fee_coins = collect_fees(pool);
    swap_exact_x_to_y_direct(pool, fee_coins); // this calls distribute_fees!
}

public fun swap_exact_x_to_y_direct<X, Y>(
    pool: &mut Pool<X, Y>, coins: Coin<X>
): Coin<Y> {
    // ... swap logic ...
    distribute_fees(pool); // infinite recursion!
}
```

**Check:**
1. Trace call chains for cycles — especially fee distribution that calls swap internally
2. Any function that both triggers and is triggered by the same action
3. Look for functions called in hooks/callbacks that can re-enter the calling function

*Real audit ref: Baptswap (distribute_dex_fees → swap → distribute_dex_fees — High)*

### 10.2 Flash Loan Accumulator Manipulation

**Pattern:** Stake/unstake in the same transaction to manipulate reward accumulators.

```move
// VULNERABLE — accumulator updates on every stake/unstake
public fun stake(pool: &mut Pool, amount: u64) {
    update_reward_accumulator(pool);  // updates based on current total_staked
    pool.total_staked = pool.total_staked + amount;
}

public fun unstake(pool: &mut Pool, amount: u64): u64 {
    update_reward_accumulator(pool);  // updates again
    pool.total_staked = pool.total_staked - amount;
    calculate_and_return_rewards(pool) // inflated rewards!
}

// Attack: flash_loan → stake(huge) → unstake + claim rewards → repay
```

**Check:**
1. Can stake + claim + unstake happen in the same transaction/PTB?
2. Does the accumulator use time-weighted values or instant values?
3. Is there a minimum staking duration before rewards are claimable?
4. Does `total_staked` changing mid-tx affect other users' reward share?

*Real audit refs: Thala Labs (improper accumulator updates — Critical, 2x),
Kofi Finance (kAPT double minting — High)*

### 10.3 Cooldown / Timelock Bypass via Inverted Logic

**Pattern:** Wrong comparison operator or inverted boolean makes time-based protection useless.

```move
// VULNERABLE — wrong operator, allows action BEFORE cooldown expires
public fun withdraw(state: &State, clock: &Clock) {
    let elapsed = clock::timestamp_ms(clock) - state.last_action;
    assert!(elapsed < COOLDOWN_PERIOD, E_COOLDOWN); // BUG: should be >=
}

// VULNERABLE — zero value bypasses the entire check
public fun check_time(end_time: u64, now: u64) {
    if (end_time != 0 && end_time < now) { abort E_EXPIRED };
    // BUG: end_time == 0 skips check entirely
}

// SAFE
public fun withdraw(state: &State, clock: &Clock) {
    let elapsed = clock::timestamp_ms(clock) - state.last_action;
    assert!(elapsed >= COOLDOWN_PERIOD, E_COOLDOWN_NOT_MET);
}
```

**Check:**
1. Every time comparison: verify operator direction matches intent (`>=` for "after", `<` for "before")
2. Check for zero-value bypass in time fields (if `time == 0`, is the check skipped?)
3. Verify boolean conditions aren't inverted

*Real audit refs: Elixir (wrong comparison, cooldown bypass — High),
Securitize (inverted logic, zero never aborts — Critical)*

### 10.4 Incorrect Liquidation Logic

**Pattern:** Liquidation functions that pass the wrong variable, skip solvency checks, or miscalculate amounts.

```move
// VULNERABLE — burns collateral amount instead of debt amount
public fun liquidate(position: &mut Position, collateral_to_seize: u64, debt_to_repay: u64) {
    burn_debt_tokens(position, collateral_to_seize); // BUG: should be debt_to_repay!
    transfer_collateral(position, collateral_to_seize);
}

// VULNERABLE — no solvency check after withdrawal
public fun withdraw(account: &mut Account, amount: u64) {
    account.balance = account.balance - amount;
    // Missing: assert!(is_solvent(account), E_WOULD_BE_INSOLVENT);
}
```

**Check:**
1. Verify the correct variable (debt vs collateral) is passed at each step in the liquidation flow
2. `withdraw` must check solvency AFTER the withdrawal, not before
3. Liquidation must not be blockable by cooldowns, paused states, or other guards
4. Verify liquidation incentive math doesn't let liquidators extract more than intended

*Real audit refs: AAVE v3 (collateral burned instead of debt — High),
Echelon (missing solvency check — High),
Aries Markets (settle_share_amount wrong conversion — High)*

---

## 11. Cross-Module Lifecycle

### 11.1 Cross-Module Terminal State Cleanup

**Pattern:** When any function — especially a permissionless one — can transition an
obligation or position to a terminal state (zero debt, zero collateral,
fully liquidated, fully repaid), ALL associated sub-objects across ALL
modules must have a cleanup path.

In Move, sub-objects are typically stored in separate modules:
- Reward / liquidity mining trackers
- Referral fee entries
- Rate limiter records
- eMode group membership entries
- Insurance fund records

If a sub-object has no cleanup path when its parent reaches terminal state,
AND a permissionless function can trigger that terminal state, the result is a
permanently orphaned object that can block admin operations forever.

The highest-risk combination is:
`permissionless_fn → terminal_state → orphaned_tracker → blocks_admin_fn`

**Risk:** Admin-funded resources (reward pools, insurance reserves) can be
permanently locked with no upgrade path in an immutable contract.

```move
// VULNERABLE — repay_on_behalf can clear last debt but reward tracker is orphaned
// In repay.move:
public fun repay_on_behalf(
    obligation: &mut Obligation,
    payment: Coin<USDC>,
    _ctx: &mut TxContext,
) {
    let amount = coin::value(&payment);
    obligation.debt = obligation.debt - amount;
    // BUG: no cleanup of reward tracker in liquidity_mining module
    // If debt == 0, obligation is terminal but tracker persists
}

// In liquidity_mining.move:
public fun close_pool_reward(
    _cap: &AdminCap,
    pool: &mut RewardPool,
) {
    // Checks that no active trackers remain
    assert!(pool.active_trackers == 0, E_TRACKERS_EXIST);
    // Orphaned tracker blocks this forever → reward tokens locked
    let rewards = balance::withdraw_all(&mut pool.rewards);
    // ...
}

// SAFE — repayment cleans up all cross-module state on terminal transition
public fun repay_on_behalf(
    obligation: &mut Obligation,
    mining_pool: &mut RewardPool,
    payment: Coin<USDC>,
    _ctx: &mut TxContext,
) {
    let amount = coin::value(&payment);
    obligation.debt = obligation.debt - amount;
    if (obligation.debt == 0) {
        // Clean up reward tracker on terminal state
        cleanup_reward_tracker(mining_pool, object::id(obligation));
    };
}
```

**Check:**
1. For every permissionless function that can fully repay, fully redeem, or
   fully liquidate a position — list all modules that hold per-obligation state
2. For each: does the permissionless function (or a function it calls) clean
   up that module's record when the position reaches terminal state?
3. Find admin/maintenance functions (`close_pool`, `collect_fees`, `end_epoch`)
   that check for "zero active trackers" or "empty registry" before executing
4. If any such admin function can be permanently blocked by an orphaned
   tracker that a permissionless function can create → HIGH
5. Search for permissionless entry functions (no capability arg) that call
   repay, liquidate, or withdraw; grep all other module files for
   structs keyed by `ObligationID` or `PositionID`; verify cleanup calls exist

---

## 12. Arithmetic / Accounting DoS

### 12.1 Abort-Before-Checkpoint Deadlock

**Pattern:** A periodic accounting function (reward accumulator update, interest accrual, index refresh) performs arithmetic that can abort, and the state checkpoint (`last_update_time`, `cumulative_index`, `reward_per_share`) is written **after** the potentially-aborting line. If the arithmetic aborts, the checkpoint never advances. On the next call, the time delta is even larger, making the overflow worse — the function is permanently uncallable.

**Risk:** Every operation that calls the stuck accounting function also reverts. In lending protocols, this typically freezes deposits, withdrawals, borrows, repayments, liquidations, and reward claims for the affected pool/CoinType. Undercollateralized positions cannot be liquidated, causing unbounded bad debt.

```move
// VULNERABLE — checkpoint written AFTER the overflowing computation
public fun update_pool_reward(pool_reward: &mut PoolReward, clock: &Clock) {
    let now = clock::timestamp_ms(clock);
    let time_passed = now - pool_reward.last_update_time_ms;     // grows every second

    // This line aborts when total_rewards * time_passed > U64_MAX
    let unlocked = float::from(pool_reward.total_rewards)
        .mul(float::from(time_passed))                            // <-- ABORT
        .div(float::from(pool_reward.duration));

    pool_reward.accumulated = pool_reward.accumulated + unlocked;
    pool_reward.last_update_time_ms = now;                        // <-- NEVER REACHED
}

// SAFE — reorder arithmetic OR checkpoint before risky computation
// Option A: divide first (prevents overflow)
let unlocked = float::from(pool_reward.total_rewards)
    .div(float::from(pool_reward.duration))
    .mul(float::from(time_passed));

// Option B: cap time_passed to remaining duration
let time_passed = math::min(time_passed, pool_reward.end_time_ms - pool_reward.last_update_time_ms);
```

**Check:**
1. For every periodic update function (grep: `last_update`, `last_accrual`, `last_checkpoint`, `cumulative_index`, `reward_per_share`):
   - Is the checkpoint variable written AFTER potentially-aborting arithmetic?
   - If the function aborts, does the time delta grow on every retry?
2. If yes → apply the **Recoverability Matrix** below

### 12.2 Admin-Origin Latent User DoS

**Pattern:** An admin performs a normal, expected configuration action (adding rewards, setting parameters, enabling a feature). The configuration is valid and reasonable at creation time. Later, under production conditions (pool inactivity, time passage, token accumulation), the configuration causes a user-facing function to abort. The admin action is the **origin**, but the **victims** are unprivileged users and liquidators.

**Risk:** This is commonly dismissed as "admin-only" or "trusted admin." That is incorrect when:
- The admin action is routine and expected (adding a reward program, setting a fee)
- The failure occurs later in a permissionless code path
- Users/liquidators are the ones blocked, not the admin
- The admin cannot fix it because recovery paths traverse the same failing code

**Severity Rule:** Severity is based on **who is blocked and what is blocked**, not who created the initial configuration.
- Users cannot withdraw → fund lock → **High/Critical**
- Liquidations blocked → bad debt accumulation → **High**
- Only admin convenience impacted → **Low/Medium**

**Check:**
1. For every admin-configurable parameter that enters a mathematical expression in a user-facing path:
   - Can the configured value, combined with elapsed time or accumulated state, overflow?
   - What is the maximum safe value? Express in atomic units with token decimals.
   - What is the realistic operational range? (e.g., 500K USDC reward over 30 days)
2. Never dismiss a finding as "admin-only" if users or liquidators are bricked
3. Cross-ref: 2.6, 12.1, DEFI-85

### Recoverability Matrix (mandatory for every DoS candidate)

For every suspected DoS/deadlock, answer ALL of these before assigning severity:

| Question | Answer |
|----------|--------|
| **What call first aborts?** | Name the exact function and line |
| **Does abort occur before checkpoint/state advance?** | If yes → state is stuck |
| **Does the failing condition worsen over time?** | e.g., time_delta grows → overflow gets worse |
| **Can admin cancel/close/modify to fix?** | Trace cancel/close paths — do they call the same update? |
| **Can users claim/withdraw to work around it?** | Trace claim/withdraw — do they also trigger the update? |
| **Is there an emergency/bypass path?** | Admin pause, emergency withdraw, governance override? |
| **Is the deadlock temporary, conditional, or permanent?** | Temporary: resolves on its own; Conditional: requires specific action; Permanent: only fixable by protocol upgrade |

**Severity from matrix:**
- Permanent deadlock + fund lock + no bypass → **Critical**
- Permanent deadlock + blocked liquidations → **High**
- Conditional deadlock with admin recovery path → **Medium**
- Temporary DoS that self-resolves → **Low**

**Example — Reward Manager Overflow:**

| Question | Answer |
|----------|--------|
| What call first aborts? | `update_pool_reward_manager` at `float::from(total_rewards).mul(float::from(time_passed))` |
| Before checkpoint? | Yes — `last_update_time_ms` is written after the abort point |
| Worsens over time? | Yes — `time_passed` grows every millisecond |
| Admin cancel? | `cancel_pool_reward` calls `update_pool_reward_manager` → also aborts |
| User claim? | `claim_rewards` calls `update_pool_reward_manager` → also aborts |
| Emergency bypass? | None — no function modifies `last_update_time_ms` without calling update |
| Duration? | **Permanent** — only fixable by protocol version upgrade |

**Result:** Permanent fund freeze + blocked liquidations → **High**

---

## 13. Build & Test Log Analysis

> **Prerequisite:** This section runs ONLY when `BUILD_AVAILABLE = true` (the project
> compiles successfully). If the project does not build, skip this entire section.
> The auditor sets this flag during Phase 1 of the SKILL.md workflow.

### Why test logs matter for security audits

Test suites exercise code paths that static analysis reads but never runs. Test logs can
reveal arithmetic aborts, assertion failures, unexpected error codes, and edge-case panics
that the developer may have papered over with `#[expected_failure]` annotations — or that
indicate latent bugs the developer hasn't noticed. A test that passes with
`#[expected_failure(abort_code = ...)]` is the developer **acknowledging** an abort exists.
The auditor's job is to determine whether that abort can happen in production under
realistic conditions.

### 13.1 Build Verification

**Procedure:**
1. Check for `Move.toml` in the project root (or `sources/` structure)
2. Run the appropriate build command:
   - **Sui:** `sui move build 2>&1` — capture stdout + stderr
   - **Aptos:** `aptos move compile 2>&1` — capture stdout + stderr
3. If build succeeds (exit code 0) → proceed to 13.2
4. If build fails → record build errors in the audit summary under "Auditor Notes".
   Build failures themselves can be informative:
   - Missing dependencies → potential supply chain risk (cross-ref 7.5)
   - Type errors → possible upgrade incompatibility (cross-ref APT-22)
   - Unused imports/variables → may indicate incomplete refactoring
   Do NOT run test log analysis on a project that does not compile.

### 13.2 Test Execution & Log Capture

**Procedure:**
1. Run the full test suite and capture all output:
   - **Sui:** `sui move test 2>&1` — capture full output
   - **Aptos:** `aptos move test 2>&1` — capture full output
2. If the project has custom test commands (check `Makefile`, `justfile`, `package.json`
   scripts, or README), run those as well
3. Save the raw test output for analysis

**Important:** If the test suite is very large (>5 minutes), run with `--filter` on
security-critical modules first (modules containing financial math, access control,
or state-mutating entry points).

### 13.3 Log Analysis — What to Look For

Analyze the test output systematically. For each category below, search the logs
and flag anything suspicious:

**Category 1 — Arithmetic Aborts (High-signal for overflow/underflow bugs)**
- Search for: `arithmetic error`, `ARITHMETIC_ERROR`, `overflow`, `underflow`,
  `abort code 4001` (Move stdlib arithmetic), `MoveAbort`, `execution failed`
- For each abort found:
  - Is it inside an `#[expected_failure]` test? If yes → the developer knows about it.
    Ask: **can this abort happen in production, not just tests?**
  - Is it in a test that exercises a user-facing code path (deposit, withdraw, borrow,
    repay, liquidate, claim)? If yes → potential DoS vector
  - What function and module does it trace back to?
  - Cross-ref: Section 2 (Arithmetic & Overflow), Section 12 (Arithmetic/Accounting DoS)

**Category 2 — Assertion Failures (Medium-signal for invariant violations)**
- Search for: `assertion failure`, `ABORTED`, `abort code`, `E_` error constant names
- For each assertion failure:
  - What invariant is being checked?
  - Is the test intentionally triggering the assertion (negative test) or is it unexpected?
  - If a positive test (should-succeed test) hits an assertion → likely a real bug
  - Cross-ref: Section 4 (Logic & Invariant Violations)

**Category 3 — Expected Failure Annotations (Medium-signal for papered-over bugs)**
- Search for: `#[expected_failure]`, `expected_failure(abort_code`
- For each expected-failure test:
  - What abort code is expected? Map it back to the error constant and the assert that fires
  - Is the abort a legitimate input validation (e.g., "zero amount rejected") or does it
    indicate a code path that aborts when it shouldn't (e.g., "overflow in reward calc")?
  - **Key question:** If this abort fires in production, does it block user operations?
  - Tests that expect arithmetic overflow aborts in financial functions are HIGH PRIORITY —
    the developer is acknowledging the overflow exists

**Category 4 — Test Failures / Skipped Tests (Low-signal but informative)**
- Search for: `FAILED`, `test result: FAILED`, `ignored`, `filtered out`
- Failing tests may indicate:
  - Incomplete implementation (code under development)
  - Regression from recent changes
  - Edge cases the developer hasn't fixed yet
- Skipped/ignored tests deserve review — they may have been disabled because they
  exposed problematic behavior

**Category 5 — Gas / Execution Limits (Low-signal for DoS)**
- Search for: `OUT_OF_GAS`, `EXECUTION_LIMIT_REACHED`, `timeout`
- Functions hitting gas limits in tests may indicate unbounded loops or excessive
  computation — potential DoS in production

### 13.4 Triage & Escalation

For each flagged log entry, apply this triage:

| Log Signal | Initial Priority | Escalation Criteria |
|------------|-----------------|---------------------|
| Arithmetic abort in user-facing path | High | If abort occurs before state checkpoint (→ 12.1), escalate to Critical investigation |
| Expected-failure test for overflow in financial math | High | Cross-check with DEFI-85/DEFI-86 — if overflow is reachable with production values, report |
| Assertion failure in positive test | Medium | Investigate the invariant — is it reachable from external inputs? |
| Expected-failure for input validation | Low | Usually legitimate — verify the validation is correct |
| Failing/skipped test | Info | Note in Auditor Notes unless it reveals a security pattern |
| Gas limit hit | Medium | Check if the function is user-callable with attacker-controlled iteration count |

**Escalation rule:** Any arithmetic abort or overflow-related `#[expected_failure]` in
a module that handles financial state (balances, rewards, interest, shares) MUST be
cross-referenced against the vulnerability patterns in this file. The auditor must:
1. Trace the abort back to the exact function and line
2. Determine if the abort is reachable from a user-facing entry point
3. If reachable → apply the Recoverability Matrix (Section 12.1)
4. Report findings to human for manual verification with:
   - The exact test name and abort code
   - The production code path that can trigger it
   - Whether the abort occurs before a state checkpoint
   - A severity assessment based on the Recoverability Matrix

### 13.5 Reporting Test Log Findings

Test log findings are reported in a separate subsection of the audit report:

```
## Test Log Analysis

**Build Status:** ✅ Compiled successfully | ❌ Build failed (see Auditor Notes)
**Test Results:** X passed, Y failed, Z skipped
**Flags Raised:** N items requiring investigation

### [TEST-NNN] Flag Title

| Field | Value |
|-------|-------|
| Priority | High / Medium / Low / Info |
| Test Name | `test_module::test_function_name` |
| Log Signal | Arithmetic abort / Expected failure / Assertion / etc. |
| Production Path | function_name in module_name.move:line |
| Checkpoint Safe? | Yes (abort after checkpoint) / No (abort before checkpoint) |

**Analysis:** What the test log revealed and why it may indicate a security issue.

**Recommendation:** Further manual investigation needed / Confirmed as vulnerability (cross-ref FINDING-NNN) / Benign
```

**Integration with main findings:** If a test log flag confirms or strengthens a finding
from Phases 3–5, cross-reference it in the main finding's Verification section rather than
duplicating it. Test log evidence increases finding confidence from QUESTIONABLE to VALID.

---

## Verification Checklist

Run through each item and mark ✅ (clean) or ❌ (finding):

- [ ] All entry functions have access control
- [ ] No capability structs with `copy` ability
- [ ] No authorization functions returning bool with unchecked call sites — use assert pattern (1.6)
- [ ] All arithmetic checked for overflow/underflow DoS
- [ ] No division before multiplication in financial math
- [ ] All divisions guarded against zero denominator
- [ ] No narrowing casts without bounds assertions
- [ ] All bitwise operations checked for overflow/precision loss — Move does NOT auto-check these (2.5)
- [ ] All `move_from` calls preceded by ownership check
- [ ] No timestamp dependencies exploitable in <30s window
- [ ] All user inputs validated (zero checks, bounds checks)
- [ ] State consistent before all external calls
- [ ] No stale reads before external calls that internally mutate the read value (6.4)
- [ ] Initialization is one-time-only
- [ ] Upgrade authority is governed or noted
- [ ] Pause flag checked on ALL public/entry functions, not just some (7.4)
- [ ] All git dependencies in Move.toml pinned with `rev` or `tag` (7.5)
- [ ] All generic type parameters validated against stored/expected types (8.1)
- [ ] Multi-return functions return values in documented order (8.2)
- [ ] No self-referential or always-true validation checks (8.3)
- [ ] All constants verified: time (86400/day), precision, MAX values correct digit count (8.4)
- [ ] Every claim/refund/withdraw updates state to prevent re-invocation (9.1)
- [ ] No mixed scaled/unscaled values in arithmetic (9.2)
- [ ] Every fee collection has a corresponding withdrawal function (9.3)
- [ ] Self-transfers cannot manipulate reward/fee snapshots (9.4)
- [ ] Round-trip `deposit→withdraw` never returns more than input (9.5)
- [ ] No circular/recursive function call chains (10.1)
- [ ] Stake/unstake cannot manipulate reward accumulators in same transaction (10.2)
- [ ] All time comparisons use correct operator direction (10.3)
- [ ] No inverted security logic — assert conditions check the right party and correct comparison direction (4.5)
- [ ] No wrong-field updates — set/update functions modify the intended field, not a same-typed sibling (4.6)
- [ ] Liquidation functions pass correct variables — debt vs collateral (10.4)
- [ ] Permissionless terminal-state transitions clean up all cross-module sub-objects (11.1)
- [ ] All fixed-point helper libraries opened and value bounds derived — `mul` intermediate cannot overflow before normalizing division (2.6)
- [ ] Every periodic accounting update writes checkpoint BEFORE or ATOMICALLY WITH potentially-aborting arithmetic (12.1)
- [ ] Admin-configured parameters validated against overflow bounds using production-realistic values and token decimals (12.2)
- [ ] Recoverability Matrix completed for every DoS candidate — cancel/claim/close paths checked for shared failure (12.1, 12.2)
- [ ] Build & test log analysis completed (if project is buildable) — arithmetic aborts, assertion failures, and error patterns reviewed (13)

> **Deep-dive prompts and the Move Vulnerability Patterns prompt pack have been moved to
> `audit-prompts.md` in this directory.** Load that file for targeted per-module,
> per-function, and adversarial-scenario prompts derived from 1141 real findings
> across 200+ Move audit reports.
