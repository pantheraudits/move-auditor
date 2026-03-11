# DeFi Liquidation — Move

Liquidation vulnerability patterns for Move lending/borrowing protocols.

---

## DEFI-50 — No Liquidation Incentive

**Description:** Liquidation provides no bonus to the liquidator. Without economic
incentive, trustless liquidators won't spend gas, leading to bad debt accumulation.

**Pattern:**
```move
// VULNERABLE — liquidator receives exactly the debt value, no bonus
public fun liquidate(position: &mut Position, repayment: Coin<Debt>): Coin<Collateral> {
    let repay_value = coin::value(&repayment);
    withdraw_collateral(position, repay_value) // no profit
}

// SAFE — liquidation bonus incentivizes liquidators
public fun liquidate(position: &mut Position, repayment: Coin<Debt>): Coin<Collateral> {
    let repay_value = coin::value(&repayment);
    let bonus = repay_value * LIQUIDATION_BONUS_BPS / 10000; // 5-10%
    withdraw_collateral(position, repay_value + bonus)
}
```

**Check:** Bonus must exist (5-15%) and exceed gas costs. Cross-ref: DEFI-06

---

## DEFI-51 — No Incentive for Small Positions

**Description:** Dust positions cost more gas to liquidate than the bonus provides.

**Pattern:**
```move
// VULNERABLE — no minimum position size
public fun borrow<T>(account: &mut Account, amount: u64) {
    add_debt(account, amount); // amount = 1 is allowed
}

// SAFE — enforce minimum borrow size
public fun borrow<T>(account: &mut Account, amount: u64) {
    assert!(amount >= MIN_BORROW_AMOUNT, E_BELOW_MINIMUM);
    add_debt(account, amount);
}
```

**Check:** Enforce minimum position sizes. `bonus * min_position > gas_cost`?

---

## DEFI-52 — Collateral Withdrawal Eliminates Liquidation Incentive

**Description:** User withdraws to just above liquidation threshold. Any price drop
causes bad debt with minimal collateral.

**Pattern:**
```move
// VULNERABLE — allows withdrawal to exact liquidation threshold
public fun withdraw_collateral(account: &mut Account, amount: u64) {
    remove_collateral(account, amount);
    assert!(health_factor(account) >= THRESHOLD, E_UNHEALTHY);
}

// SAFE — enforce borrow threshold (higher buffer)
public fun withdraw_collateral(account: &mut Account, amount: u64) {
    remove_collateral(account, amount);
    assert!(health_factor(account) >= BORROW_THRESHOLD, E_INSUFFICIENT);
}
```

**Check:** Withdrawal must enforce BORROW threshold, not LIQUIDATION threshold.

---

## DEFI-53 — No Bad Debt Handling Mechanism

**Description:** When debt exceeds collateral, no mechanism absorbs the loss.

**Pattern:**
```move
// VULNERABLE — bad debt ignored, protocol becomes insolvent
public fun liquidate(position: &mut Position, repayment: Coin<USDC>) {
    let remaining = position.debt - coin::value(&repayment);
    if (remaining > 0 && position.collateral == 0) { /* nothing happens */ };
}

// SAFE — insurance fund absorbs bad debt
public fun liquidate(position: &mut Position, insurance: &mut InsuranceFund, repayment: Coin<USDC>) {
    let remaining = position.debt - coin::value(&repayment);
    if (remaining > 0 && position.collateral == 0) {
        balance::split(&mut insurance.balance, remaining);
        position.debt = 0;
    };
}
```

**Check:** Protocol needs insurance fund or socialized loss mechanism.

---

## DEFI-54 — Partial Liquidation Bypass

**Description:** (a) Partial liquidation lets liquidators cherry-pick profitable portions,
or (b) no partial liquidation means whale positions can't be liquidated.

**Pattern:**
```move
// VULNERABLE — full liquidation only
public fun liquidate(position: &mut Position, repayment: Coin<USDC>) {
    assert!(coin::value(&repayment) == position.debt, E_MUST_REPAY_ALL);
}

// SAFE — close_factor with health improvement check
public fun liquidate(position: &mut Position, repayment: Coin<USDC>) {
    let max_repay = position.debt * CLOSE_FACTOR / 10000;
    assert!(coin::value(&repayment) <= max_repay, E_EXCEEDS_CLOSE_FACTOR);
    execute_liquidation(position, repayment);
    assert!(health_factor(position) > health_factor_before, E_HEALTH_NOT_IMPROVED);
}
```

**Check:** Partial liquidation must improve health. Close_factor prevents cherry-picking.

---

## DEFI-55 — Incorrect Liquidation Reward Decimals

**Description:** Bonus calculated with wrong decimal scaling.

**Pattern:**
```move
// VULNERABLE — missing / 10000
public fun calculate_bonus(amount: u64, bonus_bps: u64): u64 {
    amount * bonus_bps  // overflow
}
// SAFE
public fun calculate_bonus(amount: u64, bonus_bps: u64): u64 {
    ((amount as u128) * (bonus_bps as u128) / 10000 as u64)
}
```

**Check:** Verify bonus arithmetic uses consistent BPS scaling. Cross-ref: DEFI-37

---

## DEFI-56 — Excessive Protocol Fees Reduce Liquidator Incentive

**Description:** Protocol fee exceeds liquidation bonus, making liquidation unprofitable.

**Check:** Verify `liquidation_bonus - protocol_fee - gas > 0`. Fee must be strictly less than bonus.

---

## DEFI-57 — Unaccounted Yield/PnL in Health Factor

**Description:** Accrued yield not included in health factor causes premature liquidation.

**Pattern:**
```move
// VULNERABLE — ignores accrued yield
public fun health_factor(pos: &Position): u64 {
    pos.deposited_collateral * get_price() * PRECISION / pos.debt
}
// SAFE — include all value components
public fun health_factor(pos: &Position): u64 {
    let value = pos.deposited_collateral * get_price() + calculate_pending_yield(pos);
    value * PRECISION / pos.debt
}
```

**Check:** Health factor must include accrued interest, pending rewards, unrealized PnL.

---

## DEFI-58 — Missing Swap Fees in Liquidation Cost Model

**Description:** Liquidator must swap seized collateral. If swap fees and price impact
aren't accounted for in the bonus, liquidation may be unprofitable.

**Check:** `liquidation_bonus > swap_fee + price_impact + gas`? Higher bonus for illiquid collateral?

---

## DEFI-59 — Oracle Sandwich Self-Liquidation

**Description:** Attacker manipulates oracle to make position appear liquidatable,
self-liquidates to extract bonus, then price normalizes.

**Pattern:**
```move
// SAFE — TWAP oracle + minimum position age
public fun liquidate(position: &mut Position, clock: &Clock) {
    assert!(clock::timestamp_ms(clock) - position.created_at > MIN_POSITION_AGE_MS,
        E_POSITION_TOO_YOUNG);
    let price = get_twap_price(position.collateral_type);
}
```

**Check:** Can user create + liquidate in same tx/epoch? TWAP or spot oracle? Cross-ref: DEFI-01

---

## DEFI-60 — Unbounded Loops in Liquidation Path

**Description:** Liquidation iterates over unbounded collateral list, exceeding gas limit.

**Pattern:**
```move
// VULNERABLE — iterates all collateral types
public fun liquidate(account: &mut Account) {
    let i = 0;
    while (i < vector::length(&account.collaterals)) {
        seize_collateral(vector::borrow_mut(&mut account.collaterals, i));
        i = i + 1;
    };
}
// SAFE — liquidate specific collateral
public fun liquidate(account: &mut Account, idx: u64) {
    assert!(idx < vector::length(&account.collaterals), E_INVALID);
    seize_collateral(vector::borrow_mut(&mut account.collaterals, idx));
}
```

**Check:** No unbounded loops. Limit max collateral types. Cross-ref: APT-10

---

## DEFI-61 — Front-Running Liquidation

**Description:** Position owner front-runs by repaying minimal amount to raise health
factor above threshold. Liquidation tx fails.

**Check:** Anti-front-running mechanism needed (e.g., Dutch auction). On Sui: shared
object ordering may help. On Aptos: mempool ordering matters.

---

## DEFI-62 — Pending Withdrawal Blocking Liquidation

**Description:** Pending withdrawal locks collateral from seizure.

**Pattern:**
```move
// VULNERABLE — pending withdrawal reduces seizable collateral to ~0
public fun liquidate(position: &mut Position) {
    let available = position.collateral - position.pending_withdrawal;
    calculate_seize(available); // nothing to seize
}
// SAFE — cancel pending withdrawals on liquidation
public fun liquidate(position: &mut Position) {
    position.pending_withdrawal = 0;
    calculate_seize(position.collateral);
}
```

**Check:** Liquidation must override all pending operations.

---

## DEFI-63 — Token Denylist/Freeze Blocking Liquidation

**Description:** Regulated coins with denylist (Sui `DenyCapV2`) or freeze (Aptos
`FungibleAsset`) block collateral transfer, preventing liquidation.

**Pattern:**
```move
// VULNERABLE — direct transfer fails if denylisted
transfer::public_transfer(collateral, liquidator);
// SAFE — escrow mechanism
escrow::deposit(escrow, collateral); // liquidator claims from escrow
```

**Check:** Fallback path for blocked transfers needed. Cross-ref: DEFI-29

---

## DEFI-64 — Interest Accumulation During Pause

**Description:** Protocol paused but interest keeps accruing. Users can't repay.
On unpause, healthy positions are instantly liquidated.

**Pattern:**
```move
// VULNERABLE — repayment blocked during pause, interest keeps accruing
public fun repay(pos: &mut Position, payment: Coin<USDC>, state: &State) {
    assert!(!state.paused, E_PAUSED);
}
// SAFE — freeze interest during pause
public fun calculate_debt(pos: &Position, state: &State, clock: &Clock): u64 {
    let elapsed = if (state.paused) {
        state.pause_timestamp - pos.last_update
    } else { clock::timestamp_ms(clock) - pos.last_update };
    pos.principal + calculate_interest(pos.principal, elapsed)
}
```

**Check:** Interest must freeze during pause or grace period after unpause. Cross-ref: DEFI-28

---

## DEFI-65 — Position Unhealthier After Liquidation

**Description:** Partial liquidation makes health factor LOWER because bonus extracts
disproportionate collateral.

**Pattern:**
```move
// VULNERABLE — no health check after
public fun partial_liquidate(pos: &mut Position, repay: u64) {
    let seize = repay + repay * BONUS_BPS / 10000;
    pos.collateral = pos.collateral - seize;
    pos.debt = pos.debt - repay;
}
// SAFE — verify health improves
public fun partial_liquidate(pos: &mut Position, repay: u64) {
    let hf_before = health_factor(pos);
    let seize = repay + repay * BONUS_BPS / 10000;
    pos.collateral = pos.collateral - seize;
    pos.debt = pos.debt - repay;
    assert!(health_factor(pos) > hf_before, E_HEALTH_NOT_IMPROVED);
}
```

**Check:** Health factor must improve after partial liquidation. Cross-ref: DEFI-54

---

## DEFI-66 — No Slippage Protection on Liquidation

**Description:** Liquidator can't specify minimum collateral received.

**Pattern:**
```move
// VULNERABLE — no minimum guarantee
public fun liquidate(pos: &mut Position, repayment: Coin<USDC>): Coin<ETH> {
    calculate_and_seize(pos, coin::value(&repayment))
}
// SAFE — liquidator specifies minimum
public fun liquidate(pos: &mut Position, repayment: Coin<USDC>, min_out: u64): Coin<ETH> {
    let c = calculate_and_seize(pos, coin::value(&repayment));
    assert!(coin::value(&c) >= min_out, E_SLIPPAGE);
    c
}
```

**Check:** Liquidation functions should accept `min_collateral_out`.

---

## DEFI-81 — Liquidation Cash Availability — Missing Pre-Check

**Description:** When a liquidation function redeems collateral ctokens to underlying
tokens in the same transaction, it must verify that the collateral reserve
has sufficient idle cash BEFORE executing the redemption. If the collateral
reserve is at high utilization (most assets borrowed out), the redemption
call will abort because `available_cash < seize_amount`, reverting the entire
liquidation transaction.

This is especially dangerous because:
1. The unhealthy position cannot be liquidated until utilization drops
2. Interest continues to accrue on the underwater position
3. The position grows toward bad debt with no remedy available
4. A malicious borrower can intentionally keep collateral reserve at
   high utilization to prevent their own liquidation

Severity is HIGH because the safety mechanism (liquidation) fails precisely
when it is needed most — at high utilization after aggressive borrowing.
Bad debt accumulates with no protocol recourse.

**Pattern:**
```move
// VULNERABLE — redeems underlying in same tx; reverts if reserve at high utilization
public fun liquidate_ctokens(
    reserve: &mut Reserve,
    position: &mut Position,
    repayment: Coin<USDC>,
    ctx: &mut TxContext,
) {
    let seize_amount = calculate_seize(position, coin::value(&repayment));
    // BUG: if available_cash < seize_amount, balance::split aborts
    let seized = balance::split(&mut reserve.underlying, seize_amount);
    transfer::public_transfer(coin::from_balance(seized, ctx), tx_context::sender(ctx));
}

// SAFE (option A) — pre-check cash availability
public fun liquidate_ctokens(
    reserve: &mut Reserve,
    position: &mut Position,
    repayment: Coin<USDC>,
    ctx: &mut TxContext,
) {
    let seize_amount = calculate_seize(position, coin::value(&repayment));
    assert!(balance::value(&reserve.underlying) >= seize_amount, E_INSUFFICIENT_CASH);
    let seized = balance::split(&mut reserve.underlying, seize_amount);
    transfer::public_transfer(coin::from_balance(seized, ctx), tx_context::sender(ctx));
}

// SAFE (option B) — liquidator receives ctokens directly, redeems separately
public fun liquidate_ctokens(
    position: &mut Position,
    repayment: Coin<USDC>,
    ctx: &mut TxContext,
): Coin<CToken> {
    let seize_amount = calculate_seize(position, coin::value(&repayment));
    // Liquidator gets ctokens; redeems for underlying in a future tx
    split_ctokens(position, seize_amount)
}
```

**Check:**
1. In the liquidation execution path, find where ctokens are converted to underlying
   (`withdraw_underlying_asset`, `balance::split`, `redeem_ctokens`, etc.)
2. Verify ONE of: (a) a pre-check exists: `assert!(available_cash >= seize_amount)`,
   (b) ctoken seizure and underlying redemption are separated — liquidator receives ctokens
   directly and redeems in a future transaction, or (c) the protocol has a bad debt write-off
   path that handles this case
3. If the liquidation redeems underlying in the same TX without (a), (b), or (c) → HIGH

---

## Liquidation Economics Validation

**Before reporting ANY liquidation finding, answer these questions:**

1. **If your "fix" were applied, would liquidation still be profitable for the liquidator?**
   Calculate: `liquidator_revenue - liquidator_cost` at current market (spot) prices.
   If your fix makes liquidation unprofitable → the fix causes bad debt → your fix is
   WORSE than the "bug."

2. **Remember: seized collateral is worth its market (spot) price, not its lagging average.**
   Using spot for seize reflects reality — the liquidator sells at spot. Using EMA/TWAP
   for seize would underpay liquidators. Cross-ref: `defi-lending-design-patterns.md` DESIGN-L1.

3. **Does the finding change who benefits, or just how much?**
   A liquidation that over-seizes by 0.1% is Low severity. A liquidation that can be blocked
   entirely is High. Scale severity to actual economic impact.

4. **Can the "victim" of the liquidation mechanism avoid the situation?**
   If a borrower can maintain health factor by adding collateral or repaying, the liquidation
   mechanism working as designed is not a finding — even if the math slightly favors the
   liquidator. That's the intended incentive.

---

## Liquidation Verification Checklist

- [ ] Liquidation bonus exists and exceeds gas costs (DEFI-50)
- [ ] Minimum position size enforced (DEFI-51)
- [ ] Collateral withdrawal uses borrow threshold, not liquidation threshold (DEFI-52)
- [ ] Bad debt handling mechanism exists (DEFI-53)
- [ ] Partial liquidation improves health factor (DEFI-54)
- [ ] Bonus arithmetic uses correct decimal scaling (DEFI-55)
- [ ] Protocol fees don't make liquidation unprofitable (DEFI-56)
- [ ] Health factor includes all accrued yield/PnL (DEFI-57)
- [ ] No unbounded loops in liquidation path (DEFI-60)
- [ ] Token denylist/freeze can't block liquidation (DEFI-63)
- [ ] Interest frozen or grace period during/after pause (DEFI-64)
- [ ] Liquidator can specify minimum collateral received (DEFI-66)
- [ ] Liquidation path checks idle cash availability before redeeming underlying (DEFI-81)
