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

## Math / Precision Verification Checklist

- [ ] All financial calculations multiply before dividing (DEFI-35)
- [ ] Minimum amounts enforced to prevent rounding-to-zero exploitation (DEFI-36)
- [ ] Cross-token calculations normalize decimals before arithmetic (DEFI-37)
- [ ] All u128→u64 casts validated against overflow (DEFI-38)
- [ ] Rounding direction favors protocol: fees round UP, withdrawals round DOWN (DEFI-39)
- [ ] Oracle price direction (A/B vs B/A) documented and verified at each use (DEFI-40)
- [ ] Time units consistent: Sui ms converted, Aptos seconds verified (DEFI-41)
- [ ] Compound interest uses binary exponentiation with u128 precision (DEFI-42)
