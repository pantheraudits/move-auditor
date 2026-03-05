# DeFi Attack Vectors — Move

Load this reference when auditing protocols involving tokens, swaps, lending, staking,
oracles, or any financial logic. These patterns apply to both Sui and Aptos Move.

---

## DEFI-01 — Oracle Manipulation

**Description:** Price oracles that can be manipulated by a single large transaction.

**Types to check:**
1. **Spot price oracles** — Using current pool ratio as price. Flashloan-manipulable.
2. **Single-source oracles** — Trusting one external module's price feed.
3. **Stale price oracles** — No staleness check on price data.
4. **Circular oracles** — Protocol A uses Protocol B's price, which uses Protocol A's price.

**Pattern to flag:**
```move
// VULNERABLE — spot price from pool ratio
let price = pool.reserve_b / pool.reserve_a;  // flash-loan manipulable
```

**Check:**
- All price reads must include a staleness assertion (e.g., `last_updated > now - MAX_STALE`)
- TWAP should be used for anything that can be economically attacked in a single transaction
- Flash loan protection: verify price is read before and after any large operation; compare

---

## DEFI-02 — Flash Loan Attack Surface

**Description:** Any protocol that can be economically attacked with a flash loan.

**Scenarios to evaluate:**
1. **Collateral inflation:** Borrow → manipulate oracle → borrow more against inflated value → repay
2. **Governance attacks:** Borrow tokens → vote → repay (if voting snapshot is same block)
3. **Sandwich attacks:** Is the protocol vulnerable to MEV sandwiching?
4. **Reentrancy-via-flash-loan:** Flash loan triggers a callback that re-enters the protocol

**Check on every lending/borrowing function:**
- Price read uses TWAP, not spot
- Any callback mechanism (flash loan repay hook) cannot re-enter the main protocol
- Governance snapshots are not in the same transaction as the vote

---

## DEFI-03 — Liquidity Pool Manipulation

**Description:** AMM/pool vulnerabilities specific to Move protocols.

**Patterns:**
1. **First depositor attack:** If pool starts empty, first depositor sets the price.
   Check: Minimum initial liquidity burned to dead address.

2. **Rounding in LP share calculation:**
   ```
   shares = (deposit * total_shares) / total_reserves
   ```
   If `total_reserves` rounds against the protocol, attackers can extract value.
   Check: Rounding direction always favors the protocol.

3. **Imbalanced pool draining:** Providing one-sided liquidity to skew pool, then swapping.
   Check: Slippage limits on all swaps.

4. **Infinite mint via precision:**
   ```move
   // 1 wei deposit → mints 1e18 shares if total_supply = 0
   ```
   Check: Dead shares minted at initialization prevent this.

---

## DEFI-04 — Loan / Borrow Invariants

**Description:** Lending protocol invariants that must hold at all times.

**Invariants to verify:**
1. `total_borrowed ≤ total_deposited` (solvency)
2. `user_borrow_value ≤ user_collateral_value * LTV` (individual solvency)
3. Liquidation threshold > borrow threshold (liquidation is possible before insolvency)
4. Interest accrual doesn't make healthy positions undercollateralized in one block

**Check:**
- Is solvency checked at the end of every borrow and withdrawal?
- Can interest accrual cause a position to become instantly liquidatable without warning?
- Are bad debt scenarios handled? What happens if liquidation profit < gas cost?

---

## DEFI-05 — Reward / Yield Calculation Errors

**Description:** Errors in reward distribution math.

**Common bugs:**

1. **Rewards before staking:** Rewards accrued from block 0 instead of from user deposit time.
2. **Reward dilution:** New stakers retroactively receive past rewards.
3. **Precision loss in accumulator:** `reward_per_token` accumulator loses precision for small stakes.
4. **Integer division in per-user share:**
   ```
   user_reward = (user_stake * reward_per_token_stored) / PRECISION
   ```
   If PRECISION is too small, large stakers lose dust rewards to rounding.

**Check:**
- Reward calculation uses the "per-token accumulator" pattern correctly
- New stakers don't receive historical rewards
- PRECISION constant is large enough (1e12 or greater recommended)
- Reward accrual handles the zero-stakers case (no division by zero)

---

## DEFI-06 — Liquidation Mechanism

**Description:** Liquidation functions that can be abused or blocked.

**Check:**

1. **Liquidation griefing:** Can a position be made impossible to liquidate?
   (e.g., by making the collateral transfer fail)

2. **Dust liquidation:** Can tiny positions never be liquidated profitably?
   → Bad debt accumulates.

3. **Liquidation bonus manipulation:** Is the liquidation bonus (incentive for liquidators)
   fixed or calculable? Can it be gamed?

4. **Partial vs full liquidation:** If partial liquidation is allowed, can an attacker
   leave a position just above the threshold to prevent full liquidation?

5. **Collateral type manipulation during liquidation:** On Sui, if collateral is a mutable
   shared object, can its value change between the liquidation check and the liquidation execution?

6. **Off-by-threshold (sequential check trap):** Multiple sequential health factor checks
   where the first is stricter than needed, blocking valid liquidations.
   ```move
   // VULNERABLE — two sequential checks, first one blocks valid liquidations
   public fun liquidate(position: &Position) {
       let hf = calculate_health_factor(position);
       assert!(hf < 9500, E_HEALTHY);  // 0.95 — too strict!
       assert!(hf < 10000, E_HEALTHY); // 1.0 — correct threshold
       // Users with HF between 0.95–1.0 are unhealthy but unliquidatable
       // Bad debt silently accumulates
   }

   // SAFE — single threshold check
   public fun liquidate(position: &Position) {
       let hf = calculate_health_factor(position);
       assert!(hf < 10000, E_HEALTHY); // only check: HF < 1.0
       // Separate close factor logic can use 0.95 threshold if needed
   }
   ```
   Check: Verify liquidation entry has only one health factor gate matching the actual
   liquidation threshold. Stricter checks (like close factor) should control *how much*
   is liquidated, not *whether* liquidation is allowed.
   *Real audit ref: Aptos AAVE fork (hf < 0.95 blocks liquidation for 0.95–1.0 accounts,
   originally caught by Certora — High)*

---

## DEFI-07 — Slippage and Front-Running

**Description:** Transactions without slippage protection are vulnerable to MEV.

**Pattern:**
```move
// VULNERABLE — no minimum output specified
public entry fun swap(
    pool: &mut Pool,
    coin_in: Coin<A>,
    ctx: &mut TxContext
): Coin<B> {
    // No min_amount_out check!
    execute_swap(pool, coin_in)
}
```

**Check:**
1. All swap functions must have a `min_amount_out` parameter
2. `min_amount_out = 0` should be disallowed or flagged as dangerous
3. Deadline parameters should be enforced for time-sensitive operations
4. On Aptos: verify that `min_amount_out` is checked against actual output, not input

---

## DEFI-08 — Interest Rate Model Safety

**Description:** Interest rate models that can be driven to extreme values.

**Check:**
1. Interest rate has a defined maximum cap (e.g., 1000% APR)
2. Interest rate calculation doesn't overflow when utilization approaches 100%
3. Compound interest calculation doesn't overflow for large time deltas
4. Division in interest calculation: verify denominator can never be zero

---

## DEFI-09 — Governance / Timelock Bypass

**Description:** Governance mechanisms that can be bypassed or short-circuited.

**Check:**
1. Proposal execution has a timelock — flag absence as High
2. Flash loan governance attacks: voting power snapshot taken before proposal, not at vote time
3. Can a whale manipulate a token price to acquire governance power in one transaction?
4. Emergency powers: who has them, and under what conditions?

---

## DEFI-10 — Bridge / Cross-Chain Patterns (Move)

**Description:** Move protocols that bridge assets between Sui ↔ Aptos or to/from EVM chains.

**Check:**
1. Message replay protection: each bridge message has a unique nonce/hash
2. Signature threshold: minimum N-of-M validators required
3. Token supply consistency: minting on destination must match burning on source
4. Validator set changes: how is the validator set updated? Can a compromised validator set update itself?
5. Finality assumptions: how many confirmations before a bridge event is considered final?

---

## DeFi Verification Checklist

- [ ] All price reads use TWAP or include staleness check
- [ ] First depositor attack mitigated (dead shares at init)
- [ ] Rounding always favors protocol, not user
- [ ] Solvency check on every borrow and withdrawal
- [ ] Reward calculation uses per-token accumulator correctly
- [ ] Liquidation profitable for all realistic collateral values
- [ ] All swap functions have min_amount_out parameter
- [ ] Interest rate model has maximum cap and no overflow
- [ ] Governance has timelock
- [ ] Bridge messages have replay protection
