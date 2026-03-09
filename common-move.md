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

## Verification Checklist

Run through each item and mark ✅ (clean) or ❌ (finding):

- [ ] All entry functions have access control
- [ ] No capability structs with `copy` ability
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
- [ ] Liquidation functions pass correct variables — debt vs collateral (10.4)

> **Deep-dive prompts and the Move Vulnerability Patterns prompt pack have been moved to
> `audit-prompts.md` in this directory.** Load that file for targeted per-module,
> per-function, and adversarial-scenario prompts derived from 1141 real findings
> across 200+ Move audit reports.
