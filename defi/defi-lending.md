# DeFi Lending Vulnerability Patterns (DEFI-25 to DEFI-34)

Deep-dive reference for auditing Move lending protocols on Sui and Aptos.
Load when code contains `borrow`, `repay`, `collateral`, `health_factor`,
`loan`, or `debt`.

---

## DEFI-25 — Premature Liquidation (Threshold Off-by-One)

**Description:** Wrong comparison operator causes positions at exactly the
liquidation threshold to be liquidatable when the spec considers them healthy.

**Pattern:**
```move
// VULNERABLE — `<` liquidates at exactly LIQUIDATION_THRESHOLD
public fun liquidate<T>(pool: &mut LendingPool, borrower: address,
    repay: Coin<T>, ctx: &mut TxContext) {
    let hf = calculate_health_factor(pool, borrower);
    assert!(hf < LIQUIDATION_THRESHOLD, E_HEALTHY); // BUG: == triggers liquidation
    execute_liquidation(pool, borrower, repay, ctx);
}

// SAFE — `<=` means only strictly-below threshold is liquidatable
public fun liquidate<T>(pool: &mut LendingPool, borrower: address,
    repay: Coin<T>, ctx: &mut TxContext) {
    let hf = calculate_health_factor(pool, borrower);
    assert!(hf <= LIQUIDATION_THRESHOLD, E_HEALTHY);
    execute_liquidation(pool, borrower, repay, ctx);
}
```

**Check:**
1. Verify `<` vs `<=` matches the protocol spec for the liquidation boundary
2. Cross-ref: DEFI-06

---

## DEFI-26 — Collateral Manipulation Between Check and Execution

**Description:** On Sui, shared-object collateral can change between PTB steps.
On Aptos, an external call between assert and seizure can mutate collateral,
causing stale data to drive the seizure amount.

**Pattern:**
```move
// VULNERABLE — read collateral, external call, then use stale value
public fun liquidate_position(pool: &mut LendingPool, vault: &mut CollateralVault,
    oracle: &PriceOracle, borrower: address, ctx: &mut TxContext) {
    let coll_val = get_collateral_value(vault, oracle, borrower);
    let debt_val = get_debt_value(pool, borrower);
    assert!((coll_val * PRECISION) / debt_val < LIQUIDATION_THRESHOLD, E_HEALTHY);
    accrue_interest(pool); // external call — vault could change
    transfer_collateral(vault, borrower, tx_context::sender(ctx),
        compute_seize(coll_val, debt_val)); // stale coll_val
}

// SAFE — settle state first, then atomically check-and-execute
public fun liquidate_position(pool: &mut LendingPool, vault: &mut CollateralVault,
    oracle: &PriceOracle, borrower: address, ctx: &mut TxContext) {
    accrue_interest(pool);
    let coll_val = get_collateral_value(vault, oracle, borrower);
    let debt_val = get_debt_value(pool, borrower);
    let health = (coll_val * PRECISION) / debt_val;
    assert!(health < LIQUIDATION_THRESHOLD, E_HEALTHY);
    transfer_collateral(vault, borrower, tx_context::sender(ctx),
        compute_seize(coll_val, debt_val));
    assert!(calculate_health_factor(pool, vault, oracle, borrower) > health, E_NOT_IMPROVED);
}
```

**Check:**
1. Look for external calls between reading collateral and seizing it
2. Cross-ref: common-move.md 6.4 (TOCTOU), SUI-02 (shared-object races)

---

## DEFI-27 — Loan Closure Without Full Repayment

**Description:** The hot-potato/receipt pattern fails to enforce full repayment
plus fees before the receipt is destroyed, allowing pool drainage.

**Pattern:**
```move
// VULNERABLE — receipt destroyed without checking repayment amount
public fun flash_repay(pool: &mut LendingPool, repayment: Coin<SUI>, receipt: FlashReceipt) {
    let FlashReceipt { borrow_amount: _, fee: _ } = receipt; // no value check
    coin::put(&mut pool.reserves, repayment);
}

// SAFE — assert full repayment before destroying receipt
public fun flash_repay(pool: &mut LendingPool, repayment: Coin<SUI>, receipt: FlashReceipt) {
    let FlashReceipt { borrow_amount, fee } = receipt;
    assert!(coin::value(&repayment) >= borrow_amount + fee, E_INSUFFICIENT_REPAYMENT);
    coin::put(&mut pool.reserves, repayment);
}
```

**Check:**
1. Verify receipt enforces `repaid >= borrow_amount + fee` before destruction
2. Check fee bypass via zero-value coin or splitting
3. Cross-ref: SUI-09 (hot-potato integrity), SUI-20 (flash loan patterns)

---

## DEFI-28 — Asymmetric Pause (Repayment Blocked, Liquidation Active)

**Description:** Protocol pauses repayments but leaves liquidation active,
creating an unfair forced-liquidation window where borrowers are helpless.

**Pattern:**
```move
// VULNERABLE — repay checks pause, liquidate does not
public fun repay<T>(pool: &mut LendingPool, payment: Coin<T>, ctx: &mut TxContext) {
    assert!(!pool.paused, E_PAUSED);
    reduce_debt(pool, tx_context::sender(ctx), coin::value(&payment));
    coin::put(&mut pool.reserves, payment);
}
public fun liquidate<T>(pool: &mut LendingPool, borrower: address,
    repay_coin: Coin<T>, ctx: &mut TxContext) {
    // BUG: no pause check — liquidation proceeds while repay is blocked
    assert!(calculate_health_factor(pool, borrower) < LIQUIDATION_THRESHOLD, E_HEALTHY);
    execute_liquidation(pool, borrower, repay_coin, ctx);
}

// SAFE — symmetric pause on both repay and liquidate
public fun liquidate<T>(pool: &mut LendingPool, borrower: address,
    repay_coin: Coin<T>, ctx: &mut TxContext) {
    assert!(!pool.paused, E_PAUSED); // symmetric with repay
    assert!(calculate_health_factor(pool, borrower) < LIQUIDATION_THRESHOLD, E_HEALTHY);
    execute_liquidation(pool, borrower, repay_coin, ctx);
}
```

**Check:**
1. Trace every function gated by `paused`; ensure repay, deposit-collateral, and liquidate are consistent
2. If liquidation is intentionally active during pause, verify a grace period exists (DEFI-30)

---

## DEFI-29 — Token Denylist/Freeze Blocking Repayment

**Description:** Sui `DenyCapV2` or Aptos `FungibleAsset` freeze blocks
transfers from denylisted addresses, preventing repayment and forcing
liquidation through no fault of the borrower.

**Pattern:**
```move
// VULNERABLE — only direct repayment; denylisted borrower tx reverts
public fun repay<T>(pool: &mut LendingPool, payment: Coin<T>, ctx: &mut TxContext) {
    reduce_debt(pool, tx_context::sender(ctx), coin::value(&payment));
    coin::put(&mut pool.reserves, payment);
}

// SAFE — third-party repayment path for denylisted borrowers
public fun repay<T>(pool: &mut LendingPool, payment: Coin<T>, ctx: &mut TxContext) {
    process_repayment(pool, tx_context::sender(ctx), payment);
}
public fun repay_on_behalf<T>(pool: &mut LendingPool, borrower: address,
    payment: Coin<T>, _ctx: &mut TxContext) {
    process_repayment(pool, borrower, payment); // payer != borrower
}
fun process_repayment<T>(pool: &mut LendingPool, borrower: address, payment: Coin<T>) {
    reduce_debt(pool, borrower, coin::value(&payment));
    coin::put(&mut pool.reserves, payment);
}
```

**Check:**
1. Identify whether any supported token is regulated/freezable
2. Verify `repay_on_behalf` or proxy-repayment exists
3. Cross-ref: SUI-21 (DenyList / regulated coin risks)

---

## DEFI-30 — No Grace Period Before Liquidation

**Description:** Positions become liquidatable and are immediately seized with
no time buffer for users to add collateral or repay.

**Pattern:**
```move
// VULNERABLE — instant liquidation the moment health drops
public fun liquidate<T>(pool: &mut LendingPool, clock: &Clock,
    borrower: address, repay_coin: Coin<T>, ctx: &mut TxContext) {
    accrue_interest(pool, clock);
    assert!(calculate_health_factor(pool, borrower) < LIQUIDATION_THRESHOLD, E_HEALTHY);
    execute_liquidation(pool, borrower, repay_coin, ctx);
}

// SAFE — require grace period after position first becomes unhealthy
public fun liquidate<T>(pool: &mut LendingPool, clock: &Clock,
    borrower: address, repay_coin: Coin<T>, ctx: &mut TxContext) {
    accrue_interest(pool, clock);
    assert!(calculate_health_factor(pool, borrower) < LIQUIDATION_THRESHOLD, E_HEALTHY);
    let now = clock::timestamp_ms(clock);
    let pos = borrow_position_mut(pool, borrower);
    if (pos.unhealthy_since == 0) {
        pos.unhealthy_since = now;
        abort E_GRACE_PERIOD_ACTIVE
    };
    assert!(now - pos.unhealthy_since >= GRACE_PERIOD_MS, E_GRACE_PERIOD_ACTIVE);
    execute_liquidation(pool, borrower, repay_coin, ctx);
}
public fun reset_grace(pool: &mut LendingPool, borrower: address) {
    if (calculate_health_factor(pool, borrower) >= LIQUIDATION_THRESHOLD) {
        borrow_position_mut(pool, borrower).unhealthy_since = 0;
    };
}
```

**Check:**
1. Look for `grace_period` or `unhealthy_since` in position state
2. Verify grace resets when health restored; evaluate interaction with DEFI-28

---

## DEFI-31 — Incorrect Liquidation Share Calculation

**Description:** Liquidation omits close factor and liquidation bonus, or
calculates seizure from the wrong base, letting the liquidator take more
collateral than warranted or liquidate the entire debt in one call.

**Pattern:**
```move
// VULNERABLE — no close_factor, no bonus, no post-check
public fun liquidate(pool: &mut LendingPool, borrower: address,
    repay_amount: u64, coll_price: u64, debt_price: u64) {
    seize_collateral(pool, borrower, (repay_amount * debt_price) / coll_price);
}

// SAFE — close_factor cap, bonus, post-health validation
public fun liquidate(pool: &mut LendingPool, borrower: address,
    repay_amount: u64, coll_price: u64, debt_price: u64) {
    let total_debt = get_total_debt(pool, borrower);
    assert!(repay_amount <= (total_debt * CLOSE_FACTOR_BPS) / 10000, E_EXCEEDS_CLOSE_FACTOR);
    let num = (repay_amount as u128) * (debt_price as u128) * (10000u128 + (BONUS_BPS as u128));
    let seize = ((num / ((coll_price as u128) * 10000u128)) as u64);
    assert!(seize <= get_collateral_balance(pool, borrower), E_INSUFFICIENT_COLLATERAL);
    seize_collateral(pool, borrower, seize);
    reduce_debt(pool, borrower, repay_amount);
    assert!(calculate_health_factor(pool, borrower) > LIQUIDATION_THRESHOLD
        || total_debt == repay_amount, E_NOT_IMPROVED);
}
```

**Check:**
1. Verify close_factor caps maximum repayable debt per call
2. Confirm bonus is bounded; check post-liquidation health validated
3. Cross-ref: DEFI-06, common-move.md 10.4

---

## DEFI-32 — Dust Position Accumulation

**Description:** `u64` arithmetic means tiny positions round repay amounts to
zero. These dust positions can never be closed, accumulating as bad debt.

**Pattern:**
```move
// VULNERABLE — small debt rounds to 0; dust remains forever
public fun calc_repay(user_debt: u64, ratio: u64): u64 {
    (user_debt * ratio) / PRECISION_BPS // (5 * 1000) / 10000 = 0
}

// SAFE — minimum position size + force-close for dust
const MIN_BORROW: u64 = 1000;
public fun borrow(pool: &mut LendingPool, amount: u64, ctx: &mut TxContext) {
    assert!(amount >= MIN_BORROW, E_BELOW_MINIMUM);
    create_loan(pool, tx_context::sender(ctx), amount);
}
public fun repay(pool: &mut LendingPool, borrower: address, amount: u64) {
    let debt = get_debt(pool, borrower);
    if (debt <= MIN_BORROW || amount >= debt) {
        reduce_debt(pool, borrower, debt); // force full closure
    } else {
        assert!(debt - amount >= MIN_BORROW, E_DUST_POSITION);
        reduce_debt(pool, borrower, amount);
    };
}
```

**Check:**
1. Verify minimum borrow size enforced at creation
2. Check partial repay cannot leave dust below minimum

---

## DEFI-33 — Forced Debt / Unauthorized Loan Creation

**Description:** Attacker forces debt onto unwilling users. On Sui, `store`
lets debt objects be transferred to victims. On Aptos, a forwarded signer
allows `move_to` at an arbitrary address.

**Pattern:**
```move
// VULNERABLE (Sui) — `store` lets anyone transfer debt to victim
public struct DebtObligation has key, store { id: UID, amount: u64 }
public fun force_debt(victim: address, ctx: &mut TxContext) {
    transfer::public_transfer(
        DebtObligation { id: object::new(ctx), amount: 1_000_000 }, victim);
}

// SAFE (Sui) — no `store`; debt bound to sender only
public struct DebtObligation has key { id: UID, borrower: address, amount: u64 }
public fun borrow(pool: &mut LendingPool, amount: u64, ctx: &mut TxContext): Coin<SUI> {
    let borrower = tx_context::sender(ctx);
    transfer::transfer(DebtObligation { id: object::new(ctx), borrower, amount }, borrower);
    withdraw_from_pool(pool, amount, ctx)
}

// VULNERABLE (Aptos) — public fun takes arbitrary signer
public fun create_debt(account: &signer, amount: u64) {
    move_to(account, DebtObligation { amount }); // forwarded signer
}

// SAFE (Aptos) — entry fun; signer is tx sender
public entry fun borrow(borrower: &signer, pool: &mut LendingPool, amount: u64) {
    let addr = signer::address_of(borrower);
    assert!(!exists<DebtObligation>(addr), E_ALREADY_HAS_DEBT);
    move_to(borrower, DebtObligation { amount });
    transfer_coins(pool, addr, amount);
}
```

**Check:**
1. On Sui: verify debt structs lack `store`
2. On Aptos: verify debt functions require borrower's own `&signer`
3. No entry point creates debt for other than sender
4. Cross-ref: SUI-04, APT-04

---

## DEFI-34 — State Manipulation via Refinancing

**Description:** Borrow + refinance in the same transaction lets the attacker
reset their interest index, skipping accumulated interest owed.

**Pattern:**
```move
// VULNERABLE — no cooldown; index reset skips owed interest
public fun borrow(pool: &mut LendingPool, clock: &Clock, amount: u64, ctx: &mut TxContext) {
    accrue_interest(pool, clock);
    let pos = get_or_create_position(pool, tx_context::sender(ctx));
    pos.borrowed = pos.borrowed + amount;
    pos.interest_index = pool.global_interest_index;
    withdraw_from_reserves(pool, amount, ctx);
}
public fun refinance(pool: &mut LendingPool, clock: &Clock, ctx: &mut TxContext) {
    accrue_interest(pool, clock);
    let pos = get_or_create_position(pool, tx_context::sender(ctx));
    pos.interest_index = pool.global_interest_index; // skips owed interest
}

// SAFE — cooldown + settle accrued interest before index reset
public fun borrow(pool: &mut LendingPool, clock: &Clock, amount: u64, ctx: &mut TxContext) {
    accrue_interest(pool, clock);
    let pos = get_or_create_position(pool, tx_context::sender(ctx));
    pos.borrowed = pos.borrowed + amount;
    pos.interest_index = pool.global_interest_index;
    pos.last_action_ts = clock::timestamp_ms(clock);
    withdraw_from_reserves(pool, amount, ctx);
}
public fun refinance(pool: &mut LendingPool, clock: &Clock, ctx: &mut TxContext) {
    accrue_interest(pool, clock);
    let pos = get_or_create_position(pool, tx_context::sender(ctx));
    let now = clock::timestamp_ms(clock);
    assert!(now - pos.last_action_ts >= MIN_REFINANCE_COOLDOWN, E_COOLDOWN);
    pos.borrowed = pos.borrowed +
        calc_accrued(pos.borrowed, pos.interest_index, pool.global_interest_index);
    pos.interest_index = pool.global_interest_index;
    pos.last_action_ts = now;
}
```

**Check:**
1. Verify minimum cooldown between borrow/refinance on the same position
2. Confirm accrued interest settled before index reset
3. Check `accrue_interest` is idempotent within a single timestamp

---

## Lending Verification Checklist

- [ ] Liquidation threshold boundary: `<` vs `<=` matches the spec (DEFI-25)
- [ ] No check-then-act gap between reading collateral and seizing it (DEFI-26)
- [ ] Flash loan receipts enforce `repaid >= borrowed + fee` before destruction (DEFI-27)
- [ ] Pause mechanism is symmetric: repay paused implies liquidation paused (DEFI-28)
- [ ] Repayment possible for denylisted/frozen addresses via proxy path (DEFI-29)
- [ ] Grace period between position becoming unhealthy and liquidation (DEFI-30)
- [ ] Liquidation uses close_factor cap, bonus, and post-health validation (DEFI-31)
- [ ] Minimum position size prevents dust; partial repay cannot leave sub-minimum remainder (DEFI-32)
- [ ] Debt objects cannot be transferred to unwilling recipients (DEFI-33)
- [ ] Cooldown between borrow and refinance; accrued interest settled before index reset (DEFI-34)
