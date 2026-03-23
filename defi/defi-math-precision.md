# DeFi Math & Precision — Move

Deep-dive patterns for arithmetic and precision vulnerabilities in Move DeFi protocols.
Move uses `u64` (max ~1.8e19) and `u128` (max ~3.4e38) — significantly smaller than
Solidity's `uint256` (max ~1.15e77), making precision issues more severe.

---

## DEFI-35 — Division Before Multiplication (DeFi Deep-Dive)

**Description:** Performing division before multiplication in financial calculations
causes precision loss that compounds across operations. In DeFi, even tiny per-operation
losses accumulate into significant fund leakage.

**Pattern:**
```move
// VULNERABLE — division before multiplication loses precision
public fun calculate_fee(amount: u64, fee_rate: u64, precision: u64): u64 {
    // If amount=1000, fee_rate=3, precision=10000:
    // (1000 / 10000) * 3 = 0 * 3 = 0 — fee completely lost
    (amount / precision) * fee_rate
}

// SAFE — multiply first, divide last
public fun calculate_fee(amount: u64, fee_rate: u64, precision: u64): u64 {
    // (1000 * 3) / 10000 = 3000 / 10000 = 0 — still rounds but less loss
    // Use u128 intermediate: (1000 * 3) / 10000 = 0 in u64 but tracks correctly at scale
    ((amount as u128) * (fee_rate as u128) / (precision as u128) as u64)
}
```

**Check:**
1. Search for any `/` operator appearing before `*` in the same expression
2. Grep: `/ .* \*` in financial calculation functions
3. Verify u128 intermediates are used for fee, share, and interest calculations
4. Cross-ref: common-move.md 2.2

---

## DEFI-36 — Rounding to Zero on Small Amounts

**Description:** Small token amounts produce zero results in reward, fee, or share
calculations. Attackers exploit this to transact for free (zero fees) or grief other
users (zero rewards distributed).

**Pattern:**
```move
// VULNERABLE — small reward rounds to zero, lost forever
public fun calculate_reward(user_stake: u64, reward_per_share: u64, precision: u64): u64 {
    // If user_stake=100, reward_per_share=5, precision=1_000_000:
    // (100 * 5) / 1_000_000 = 500 / 1_000_000 = 0
    (user_stake * reward_per_share) / precision
}

// SAFE — enforce minimum amounts, use higher precision
public fun calculate_reward(user_stake: u64, reward_per_share: u128, precision: u128): u64 {
    let reward = ((user_stake as u128) * reward_per_share) / precision;
    // Accumulate dust in a remainder tracker instead of losing it
    (reward as u64)
}
// Also enforce: assert!(user_stake >= MIN_STAKE, E_STAKE_TOO_SMALL);
```

**Check:**
1. Identify all divisions that could produce zero for realistic input ranges
2. Verify minimum amount requirements exist for deposits, stakes, and borrows
3. Check if dust/remainder is tracked or silently dropped
4. Cross-ref: DEFI-13, DEFI-32

---

## DEFI-37 — Decimal Mismatch Between Token Types

**Description:** Move tokens have configurable decimals stored in metadata. Mixing tokens
with different decimals (USDC=6, BTC=8, SUI=9, APT=8) without conversion causes
magnitude errors in value calculations.

**Pattern:**
```move
// VULNERABLE — assumes both tokens have same decimals
public fun calculate_value(amount_a: u64, price_a_in_b: u64): u64 {
    // If A has 8 decimals and B has 6 decimals:
    // 1.0 A (100_000_000) * price 50000 = 5_000_000_000_000 — wrong scale for 6-decimal token
    amount_a * price_a_in_b
}

// SAFE — normalize decimals explicitly
public fun calculate_value(
    amount_a: u64, price_a_in_b: u64,
    decimals_a: u8, decimals_b: u8, price_decimals: u8
): u64 {
    let value = (amount_a as u128) * (price_a_in_b as u128);
    let scale_adjustment = (decimals_a as u32) + (price_decimals as u32) - (decimals_b as u32);
    (value / (math::pow(10, scale_adjustment) as u128) as u64)
}
```

**Check:**
1. Identify all cross-token calculations (value, collateral ratio, swap amounts)
2. Grep: `coin::decimals`, `CoinMetadata`, `decimals` — verify these are used in math
3. Check that decimal normalization happens before comparison, not after
4. On Sui: `coin::get_decimals<T>(metadata)` — on Aptos: `coin::decimals<T>()`

---

## DEFI-38 — Unsafe Downcasting u128 to u64 in Financial Math

**Description:** Intermediate calculations use u128 for precision, then cast back to u64.
If the intermediate result exceeds `u64::MAX` (~1.8e19), the cast silently truncates
or aborts, causing incorrect financial outcomes.

**Pattern:**
```move
// VULNERABLE — u128 intermediate overflows u64 on cast
public fun calculate_shares(deposit: u64, total_supply: u64, total_assets: u64): u64 {
    let shares_u128 = (deposit as u128) * (total_supply as u128) / (total_assets as u128);
    // If total_supply is large and total_assets is small, shares_u128 > u64::MAX
    // Cast aborts in Move — DoS on all deposits
    (shares_u128 as u64)
}

// SAFE — validate before casting
public fun calculate_shares(deposit: u64, total_supply: u64, total_assets: u64): u64 {
    let shares_u128 = (deposit as u128) * (total_supply as u128) / (total_assets as u128);
    assert!(shares_u128 <= (U64_MAX as u128), E_OVERFLOW);
    (shares_u128 as u64)
}
```

**Check:**
1. Search all `as u64` casts from u128 — each is a potential truncation
2. Verify the mathematical maximum of each intermediate cannot exceed u64::MAX
3. Check if overflow causes abort (DoS) vs silent truncation (fund loss)
4. Cross-ref: common-move.md 2.4

---

## DEFI-39 — Wrong Rounding Direction

**Description:** Move integer division always truncates toward zero. In DeFi, rounding
must be protocol-favoring: round fees UP (protocol receives more), round withdrawals
DOWN (user receives less). Wrong direction leaks value from the protocol.

**Pattern:**
```move
// VULNERABLE — rounds withdrawal UP, favoring user over protocol
public fun calculate_withdrawal(shares: u64, total_assets: u64, total_shares: u64): u64 {
    // Truncation rounds down by default — correct for withdrawals
    // But if someone adds +1: (shares * total_assets + total_shares - 1) / total_shares
    // This rounds UP — user gets more than their share
    (shares * total_assets + total_shares - 1) / total_shares
}

// SAFE — round DOWN for withdrawals (protocol keeps the dust)
public fun calculate_withdrawal(shares: u64, total_assets: u64, total_shares: u64): u64 {
    (shares * total_assets) / total_shares  // natural truncation = round down
}

// SAFE — round UP for fees (protocol charges the dust)
public fun calculate_fee(amount: u64, fee_bps: u64): u64 {
    (amount * fee_bps + 9999) / 10000  // ceil division for fees
}
```

**Check:**
1. For every division: does rounding favor the protocol or the user?
2. Withdrawals/redemptions: must round DOWN (truncate)
3. Fees/interest/debt: must round UP (ceil)
4. Deposits/minting: must round DOWN (user gets fewer shares)

---

## DEFI-40 — Inverted Oracle Price Pairs

**Description:** Using price of A-in-B where B-in-A was needed. Results in inverted
calculations — if BTC/USD = 50000, accidentally using USD/BTC = 0.00002 produces
values off by a factor of 2.5 billion.

**Pattern:**
```move
// VULNERABLE — uses TOKEN/USD price to convert USD to TOKEN (inverted)
public fun usd_to_token(usd_amount: u64, token_usd_price: u64, precision: u64): u64 {
    // This calculates: usd_amount * token_usd_price — WRONG
    // Should divide by price to convert USD → TOKEN
    usd_amount * token_usd_price / precision
}

// SAFE — correct direction: divide by price to convert USD → TOKEN
public fun usd_to_token(usd_amount: u64, token_usd_price: u64, precision: u64): u64 {
    usd_amount * precision / token_usd_price
}
```

**Check:**
1. At every oracle integration: document whether price is `A/B` or `B/A`
2. Verify the math direction matches: multiply by price to go `A → B`, divide for `B → A`
3. Cross-ref: DEFI-23

---

## DEFI-41 — Time Unit Confusion (Sui ms vs Aptos seconds)

**Description:** Sui's `clock::timestamp_ms()` returns milliseconds, while Aptos's
`timestamp::now_seconds()` returns seconds. Mixing units in interest calculations,
lockup durations, or staleness checks causes 1000x errors.

**Pattern:**
```move
// VULNERABLE — Sui: using milliseconds as if they were seconds
public fun calculate_interest(principal: u64, rate_per_second: u64, last_update: u64, clock: &Clock): u64 {
    let elapsed = clock::timestamp_ms(clock) - last_update; // returns milliseconds!
    // elapsed = 60000 (1 minute in ms), but treated as 60000 seconds (16.6 hours)
    // Interest is 1000x too high
    principal * rate_per_second * elapsed / PRECISION
}

// SAFE — convert Sui ms to seconds explicitly
public fun calculate_interest(principal: u64, rate_per_second: u64, last_update_ms: u64, clock: &Clock): u64 {
    let elapsed_ms = clock::timestamp_ms(clock) - last_update_ms;
    let elapsed_seconds = elapsed_ms / 1000;
    ((principal as u128) * (rate_per_second as u128) * (elapsed_seconds as u128) / (PRECISION as u128) as u64)
}
```

**Check:**
1. On Sui: verify every `clock::timestamp_ms()` usage converts to correct unit
2. On Aptos: verify `timestamp::now_seconds()` — some Aptos code also has `now_microseconds()`
3. Check lockup/cooldown durations: `3600` could mean 3600ms (3.6s) or 3600s (1hr)
4. Cross-ref: SUI-16, common-move.md 8.4

---

## DEFI-42 — Exponentiation Precision Loss (Compound Interest)

**Description:** Compound interest via repeated multiplication loses precision at each
step. `(1 + rate)^n` computed iteratively truncates at every multiplication, causing
significant divergence from the true value over time.

**Pattern:**
```move
// VULNERABLE — iterative compounding truncates at each step
public fun compound(principal: u64, rate_bps: u64, periods: u64): u64 {
    let result = principal;
    let i = 0;
    while (i < periods) {
        result = result + (result * rate_bps / 10000); // truncation each iteration
        i = i + 1;
    };
    result
}

// SAFE — use binary exponentiation with u128 precision
public fun compound(principal: u64, rate_bps: u64, periods: u64): u64 {
    // Binary exponentiation: O(log n) multiplications, u128 intermediate
    let base = (10000 + rate_bps as u128); // 1 + rate in BPS
    let precision = 10000u128;
    let result = precision; // starts at 1.0
    let exp = periods;
    let b = base;
    while (exp > 0) {
        if (exp % 2 == 1) {
            result = result * b / precision;
        };
        b = b * b / precision;
        exp = exp / 2;
    };
    ((principal as u128) * result / precision as u64)
}
```

**Check:**
1. Search for loops with multiplication inside (`while` + `*`) — potential iterative compounding
2. Verify compound interest uses binary exponentiation or lookup tables
3. Check that u128 intermediates are used throughout the exponentiation
4. For large period counts (e.g., per-second compounding over years), verify no overflow

---

## DEFI-85 — Multiply-Before-Divide Overflow in Fixed-Point Helpers

**Description:** Fixed-point math libraries (WAD/RAY/Decimal wrappers) store scaled values and
enforce bounds internally. When `A.mul(B)` computes `(A.value * B.value) / WAD`, the
intermediate product can exceed the library's `VALUE_MAX` and abort — even though the
final result after `.div(C)` would be small. This is a hidden overflow: the calling code
looks correct (`from(x).mul(from(y)).div(from(z))`) but the helper aborts before the
division is reached.

**This bug class is HIGH/CRITICAL when:**
1. The overflowing function is called by every user-facing operation (deposit, withdraw, borrow, repay, liquidate, claim)
2. The overflow occurs before a state checkpoint (`last_update_time`, `cumulative_index`)
3. The time delta grows after each failed attempt, making recovery impossible
4. Admin recovery paths (cancel, close) also trigger the same update

**Mandatory analysis steps:**

**Step 1 — Derive helper bounds.** Open the fixed-point module. For `mul(a, b)`:
```
Internal: result = (a.value * b.value) / WAD
Bound check: result <= VALUE_MAX
Simplifies to: a.value * b.value <= VALUE_MAX * WAD
If VALUE_MAX = U64_MAX and both a, b are from(u64):
  a.value = input_a * WAD, b.value = input_b * WAD
  intermediate = input_a * WAD * input_b * WAD / WAD = input_a * input_b * WAD
  bound: input_a * input_b * WAD <= U64_MAX * WAD
  simplifies to: input_a * input_b <= U64_MAX
```

**Step 2 — Derive overflow threshold.** For the specific call site:
```
Example: float::from(total_rewards).mul(float::from(time_passed_ms))
Overflow when: total_rewards * time_passed_ms > U64_MAX (~1.844e19)

Token: USDC (6 decimals) → 500,000 USDC = 5e11 atomic units
Overflow at: time_passed_ms = U64_MAX / 5e11 = 3.69e7 ms ≈ 10.25 hours

Token: SUI (9 decimals) → 1,000 SUI = 1e12 atomic units
Overflow at: time_passed_ms = U64_MAX / 1e12 = 1.844e7 ms ≈ 5.12 hours
```

**Step 3 — Compute threshold table for realistic reward amounts:**

| Reward Amount | Token Decimals | Atomic Units | Max Inactivity Before Overflow |
|--------------|----------------|-------------|-------------------------------|
| 10,000 USDC | 6 | 1e10 | ~21.3 days |
| 100,000 USDC | 6 | 1e11 | ~2.13 days |
| 500,000 USDC | 6 | 5e11 | ~10.25 hours |
| 1,000,000 USDC | 6 | 1e12 | ~5.12 hours |
| 10,000,000 USDC | 6 | 1e13 | ~30.7 minutes |
| 1,000 SUI | 9 | 1e12 | ~5.12 hours |

**Pattern:**
```move
// VULNERABLE — mul overflows before div can normalize
let unlocked_rewards =
    float::from(pool_reward.total_rewards)
        .mul(float::from(time_passed_ms))        // aborts when product > U64_MAX
        .div(float::from(pool_reward.end_time_ms - pool_reward.start_time_ms));

// SAFE — div first, then mul (intermediate stays within bounds)
let unlocked_rewards =
    float::from(pool_reward.total_rewards)
        .div(float::from(pool_reward.end_time_ms - pool_reward.start_time_ms))
        .mul(float::from(time_passed_ms));
// (total_rewards / duration) is always <= total_rewards, so the subsequent mul
// can only overflow if time_passed > duration, which is bounded by the reward period.
```

**Check:**
1. Open EVERY fixed-point helper used by the protocol. Read `mul`, `div`, `from`. Derive the internal overflow bound.
2. For every call of the form `from(A).mul(from(B)).div(from(C))` — prove `A * B <= VALUE_MAX` OR flag it
3. Compute a threshold table using the protocol's actual token decimals and realistic amounts
4. If overflow is reachable, apply the Recoverability Matrix (common-move.md 12.1)
5. Cross-ref: common-move.md 2.6, DEFI-86

---

## DEFI-86 — Accumulator Checkpoint Liveness (Abort-Before-State-Advance)

**Description:** A periodic accumulator update function (reward index, interest accrual,
fee distribution) performs arithmetic that can abort, and the state checkpoint
(`last_update_time`, `cumulative_index`, `reward_per_share`) is written AFTER the
potentially-aborting line. Once the abort fires, the checkpoint stays stale, causing the
time delta to grow on every retry until the function becomes permanently uncallable.

**Why it matters for DeFi:** Accumulator updates are called by nearly every user-facing
operation — deposit, withdraw, borrow, repay, liquidate, claim. A stuck accumulator
freezes the entire pool.

**Pattern:**
```move
// VULNERABLE — checkpoint after abort-prone line
public fun update_pool_reward(pool: &mut Pool, clock: &Clock) {
    let now = clock::timestamp_ms(clock);
    let elapsed = now - pool.last_update_time_ms;              // grows if update fails

    let new_rewards = compute_rewards(pool.total_rewards, elapsed);  // CAN ABORT (overflow)

    pool.accumulated_rewards = pool.accumulated_rewards + new_rewards;
    pool.last_update_time_ms = now;  // <-- NEVER REACHED if compute_rewards aborts
}

// SAFE — use safe arithmetic that cannot abort, OR reorder to divide-first
public fun update_pool_reward(pool: &mut Pool, clock: &Clock) {
    let now = clock::timestamp_ms(clock);
    let elapsed = now - pool.last_update_time_ms;

    // Option A: reorder to prevent overflow (see DEFI-85)
    let rate = float::from(pool.total_rewards).div(float::from(pool.duration));
    let new_rewards = rate.mul(float::from(elapsed));

    pool.accumulated_rewards = pool.accumulated_rewards + new_rewards;
    pool.last_update_time_ms = now;
}
```

**Check:**
1. For every function that updates a cumulative accumulator or timestamp checkpoint:
   - Is there ANY arithmetic between reading `now` and writing the checkpoint?
   - Can that arithmetic abort (overflow, divide-by-zero, assertion)?
   - If it aborts, does the checkpoint remain stale?
2. If yes: trace ALL entry points that call this update:
   - User actions: deposit, withdraw, borrow, repay
   - Liquidation: liquidate, seize, ADL
   - Claims: claim_rewards, harvest
   - Admin: cancel_reward, close_pool, update_config
3. If ALL paths go through the stuck update → **permanent deadlock** → HIGH/CRITICAL
4. If some paths bypass the update → conditional deadlock → lower severity
5. Compute the time-to-overflow threshold (see DEFI-85 threshold table)
6. Cross-ref: common-move.md 12.1, DEFI-85

---

## DEFI-87 — Reward Manager Overflow Auto-Detection

**Trigger:** Any codebase containing reward distribution, liquidity mining, or incentive mechanisms with time-based unlocking.

**Pattern:** A reward manager computes unlocked rewards as `(total_rewards * time_elapsed) / duration` using a fixed-point helper. The multiply-before-divide order inside the helper causes overflow when `total_rewards * time_elapsed > VALUE_MAX`. If this computation runs inside a periodic update that gates ALL pool operations, overflow = permanent pool freeze.

**Mandatory grep patterns — run ALL of these:**
```
total_rewards.*mul.*time
time_passed.*mul.*total
unlocked.*from.*mul.*from.*div
reward.*\.mul\(.*time
update_pool_reward
update_reward_manager
update_obligation_reward
liquidity_mining.*update
```

**For every match, execute this 5-step trace:**

1. **Read the helper:** Open the fixed-point module used (e.g., `float.move`, `decimal.move`). Read `mul()`. Derive: what is the max product before abort?
2. **Compute overflow threshold:**
   ```
   For mul(from(A), from(B)) where helper bound is A * B <= U64_MAX:

   | Token     | Decimals | Reward Amount    | Atomic Units | Max time_passed before overflow |
   |-----------|----------|------------------|--------------|-------------------------------|
   | USDC      | 6        | 10,000           | 1e10         | ~21.3 days                    |
   | USDC      | 6        | 100,000          | 1e11         | ~2.13 days                    |
   | USDC      | 6        | 500,000          | 5e11         | ~10.25 hours                  |
   | USDC      | 6        | 1,000,000        | 1e12         | ~5.12 hours                   |
   | SUI       | 9        | 1,000            | 1e12         | ~5.12 hours                   |
   | SUI       | 9        | 10,000           | 1e13         | ~30.7 minutes                 |
   ```
   If ANY realistic reward configuration overflows within 30 days of inactivity → flag.

3. **Check checkpoint ordering:** Is `last_update_time_ms` (or equivalent) written AFTER the overflowing line? If yes → permanent deadlock.

4. **Trace all callers:** Does EVERY user-facing operation (deposit, withdraw, borrow, repay, liquidate, claim) call this update? Does EVERY admin recovery path (cancel_reward, close_pool) also call this update? If ALL paths trapped → no recovery → HIGH/CRITICAL.

5. **Check for admin-origin:** Is the overflow triggered by a routine admin action (adding rewards)? If the admin action is expected/routine but users are the victims → do NOT dismiss as "admin-only" (see 12.2).

**Safe patterns (do NOT flag):**
```move
// SAFE — divide first, then multiply
float::from(total_rewards).div(float::from(duration)).mul(float::from(time_passed))

// SAFE — cap time_passed to remaining duration
let time_passed = math::min(time_passed, end_time - last_update_time);

// SAFE — u256 intermediate with sufficient headroom
let unlocked = ((total_rewards as u256) * (time_passed as u256)) / (duration as u256);
```

---

## Math / Precision Verification Checklist

- [ ] All financial calculations multiply before dividing (DEFI-35)
- [ ] Minimum amounts enforced to prevent rounding-to-zero exploitation (DEFI-36)
- [ ] Cross-token calculations normalize decimals before arithmetic (DEFI-37)
- [ ] All u128→u64 casts validated against overflow (DEFI-38)
- [ ] Rounding direction favors protocol: fees round UP, withdrawals round DOWN (DEFI-39)
- [ ] Oracle price direction (A/B vs B/A) documented and verified at each use (DEFI-40)
- [ ] Time units consistent: Sui ms converted, Aptos seconds verified (DEFI-41)
- [ ] Compound interest uses binary exponentiation with u128 precision (DEFI-42)
- [ ] Fixed-point helper `mul` intermediate product cannot overflow before normalizing division (DEFI-85)
- [ ] Every accumulator checkpoint is written BEFORE or ATOMICALLY WITH potentially-aborting arithmetic (DEFI-86)
- [ ] Overflow thresholds computed with production token decimals and realistic amounts for all `from(A).mul(from(B))` calls (DEFI-85)
- [ ] Reward manager overflow: grep patterns run, threshold table computed, checkpoint ordering checked, all callers traced (DEFI-87)
