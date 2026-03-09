# DeFi Auctions & Concentrated Liquidity — Move

Vulnerability patterns for auction mechanisms and concentrated liquidity managers (CLMs)
in Move DeFi protocols. Covers liquidation auctions, Dutch auctions, NFT auctions,
and concentrated liquidity management (Cetus CLMM, Turbos, etc.).

---

## Auction Patterns

---

## DEFI-67 — Self-Bidding Timer Reset

**Description:** An auction participant (often the position owner in liquidation auctions)
bids on their own auction to reset the timer, extending it indefinitely. The borrower
avoids liquidation by perpetually refreshing the auction without actually losing collateral.

**Pattern:**
```move
// VULNERABLE — any bid resets timer, including from the position owner
public fun bid(auction: &mut Auction, bid_amount: Coin<USDC>, ctx: &mut TxContext) {
    assert!(coin::value(&bid_amount) > auction.highest_bid, E_BID_TOO_LOW);
    // Return previous highest bid
    refund_previous_bidder(auction);
    auction.highest_bid = coin::value(&bid_amount);
    auction.highest_bidder = tx_context::sender(ctx);
    auction.end_time = auction.end_time + TIME_EXTENSION; // timer reset!
}

// SAFE — prevent self-bidding and cap total extensions
public fun bid(auction: &mut Auction, bid_amount: Coin<USDC>, ctx: &mut TxContext) {
    let sender = tx_context::sender(ctx);
    assert!(sender != auction.position_owner, E_SELF_BID_PROHIBITED);
    assert!(coin::value(&bid_amount) > auction.highest_bid, E_BID_TOO_LOW);
    refund_previous_bidder(auction);
    auction.highest_bid = coin::value(&bid_amount);
    auction.highest_bidder = sender;
    // Cap total extensions
    let new_end = auction.end_time + TIME_EXTENSION;
    let max_end = auction.start_time + MAX_AUCTION_DURATION;
    auction.end_time = if (new_end < max_end) { new_end } else { max_end };
}
```

**Check:**
1. Can the position owner / auction creator bid on their own auction?
2. Is there a cap on total auction duration (max extensions)?
3. Does each bid require a meaningful increase (e.g., 5% minimum increment)?

---

## DEFI-68 — Insufficient Auction Length Validation

**Description:** Auction duration can be set to zero or very short values, allowing
the creator or an attacker to seize assets immediately or with minimal competition.

**Pattern:**
```move
// VULNERABLE — no minimum auction duration
public fun create_auction(
    admin_cap: &AdminCap,
    item: Object,
    duration: u64,
    clock: &Clock,
    ctx: &mut TxContext
) {
    // duration = 1 (1 millisecond) → auction ends instantly
    let auction = Auction {
        item,
        end_time: clock::timestamp_ms(clock) + duration,
        // ...
    };
}

// SAFE — enforce minimum duration
const MIN_AUCTION_DURATION_MS: u64 = 3_600_000; // 1 hour minimum

public fun create_auction(
    admin_cap: &AdminCap,
    item: Object,
    duration: u64,
    clock: &Clock,
    ctx: &mut TxContext
) {
    assert!(duration >= MIN_AUCTION_DURATION_MS, E_DURATION_TOO_SHORT);
    let auction = Auction {
        item,
        end_time: clock::timestamp_ms(clock) + duration,
    };
}
```

**Check:**
1. Is there a minimum auction duration? Flag absence as High
2. Can admin set duration to 0 or 1?
3. On Aptos: check seconds vs milliseconds in duration

---

## DEFI-69 — Off-by-One Auction Seizure

**Description:** Using `>=` instead of `>` (or vice versa) in the auction end time
comparison allows seizure one timestamp unit before the auction truly ends, or
prevents seizure at exactly the end time.

**Pattern:**
```move
// VULNERABLE — off-by-one allows seizure during active auction
public fun seize(auction: &Auction, clock: &Clock): Object {
    // >= means seizure possible at exactly end_time, while auction
    // should still be active until end_time passes
    assert!(clock::timestamp_ms(clock) >= auction.end_time, E_AUCTION_ACTIVE);
    // A bidder could bid at end_time, then seizure happens in same ms
    remove_item(auction)
}

// SAFE — strictly after end_time
public fun seize(auction: &Auction, clock: &Clock): Object {
    assert!(clock::timestamp_ms(clock) > auction.end_time, E_AUCTION_ACTIVE);
    remove_item(auction)
}
```

**Check:**
1. Verify `>` vs `>=` in all timestamp comparisons for auction boundaries
2. Check both auction start and end conditions for off-by-one
3. Ensure bid acceptance and seizure windows don't overlap

---

## Concentrated Liquidity Manager Patterns

---

## DEFI-70 — Missing TWAP Checks on Rebalance

**Description:** CLM rebalance operations redeploy liquidity to new tick ranges. If
rebalance doesn't check TWAP, an attacker can sandwich the rebalance: manipulate spot
price → trigger rebalance at wrong tick range → reverse manipulation → profit.

**Pattern:**
```move
// VULNERABLE — rebalance uses spot price, no TWAP protection
public fun rebalance(
    clm: &mut CLMVault,
    pool: &mut Pool,
    new_lower_tick: u32,
    new_upper_tick: u32,
) {
    // Removes liquidity from old range, adds to new range
    // If pool price is manipulated, new range is wrong
    let current_tick = pool::current_tick(pool);
    remove_liquidity(clm, pool);
    add_liquidity_at_range(clm, pool, new_lower_tick, new_upper_tick);
}

// SAFE — verify spot price is close to TWAP before rebalancing
public fun rebalance(
    clm: &mut CLMVault,
    pool: &mut Pool,
    new_lower_tick: u32,
    new_upper_tick: u32,
    clock: &Clock,
) {
    let spot_price = pool::current_sqrt_price(pool);
    let twap_price = pool::get_twap(pool, TWAP_WINDOW);
    let deviation = abs_diff(spot_price, twap_price) * 10000 / twap_price;
    assert!(deviation <= MAX_DEVIATION_BPS, E_PRICE_MANIPULATION);
    remove_liquidity(clm, pool);
    add_liquidity_at_range(clm, pool, new_lower_tick, new_upper_tick);
}
```

**Check:**
1. Every function that deploys/redeploys liquidity must check TWAP
2. `MAX_DEVIATION_BPS` should be reasonable (e.g., 100-500 BPS)
3. TWAP window should be long enough to resist manipulation (e.g., 30 minutes)

---

## DEFI-71 — TWAP Parameter Manipulation

**Description:** Admin can set TWAP parameters (deviation threshold, observation window)
to ineffective values, disabling protection. Setting `MAX_DEVIATION = 10000` (100%)
or `TWAP_WINDOW = 1` (1 second) effectively removes TWAP protection.

**Pattern:**
```move
// VULNERABLE — no bounds on TWAP parameters
public fun set_twap_params(
    admin_cap: &AdminCap,
    config: &mut Config,
    max_deviation: u64,
    twap_window: u64,
) {
    // Admin can set max_deviation = 10000 (100%) — no protection
    // Or twap_window = 0 — reads current price as TWAP
    config.max_deviation = max_deviation;
    config.twap_window = twap_window;
}

// SAFE — enforce parameter bounds
public fun set_twap_params(
    admin_cap: &AdminCap,
    config: &mut Config,
    max_deviation: u64,
    twap_window: u64,
) {
    assert!(max_deviation >= MIN_DEVIATION && max_deviation <= MAX_DEVIATION, E_INVALID);
    assert!(twap_window >= MIN_TWAP_WINDOW, E_INVALID); // e.g., >= 300 seconds
    config.max_deviation = max_deviation;
    config.twap_window = twap_window;
}
```

**Check:**
1. Can admin set deviation to 100% or TWAP window to 0?
2. Are there hardcoded minimum bounds for both parameters?
3. Flag missing validation as Medium (admin trust assumption)

---

## DEFI-72 — Stuck Tokens from Tick Math Rounding

**Description:** Concentrated liquidity calculations involving tick math and `u64`
precision cause rounding dust. Over many rebalances, tiny token amounts become
permanently stuck in the contract — never withdrawable.

**Pattern:**
```move
// VULNERABLE — rounding dust lost on each rebalance
public fun rebalance(clm: &mut CLMVault, pool: &mut Pool) {
    let (amount_a, amount_b) = remove_all_liquidity(clm, pool);
    // After remove: amount_a=999999, amount_b=500001
    let (used_a, used_b) = add_liquidity_at_new_range(pool, amount_a, amount_b);
    // After add: used_a=999998, used_b=500000 — 1 unit of each stuck
    // Over 1000 rebalances: 1000 units of each token permanently stuck
}

// SAFE — sweep dust back to vault or fee collector
public fun rebalance(clm: &mut CLMVault, pool: &mut Pool) {
    let (amount_a, amount_b) = remove_all_liquidity(clm, pool);
    let (used_a, used_b) = add_liquidity_at_new_range(pool, amount_a, amount_b);
    let dust_a = amount_a - used_a;
    let dust_b = amount_b - used_b;
    // Return dust to vault balance, not lost
    if (dust_a > 0) { balance::join(&mut clm.idle_a, dust_a); };
    if (dust_b > 0) { balance::join(&mut clm.idle_b, dust_b); };
}
```

**Check:**
1. After liquidity operations, is the difference between input and used amounts tracked?
2. Can accumulated dust be withdrawn by an admin or fee mechanism?
3. Over N rebalances, what's the total token loss?

---

## DEFI-73 — Retrospective Fee Application on New Liquidity

**Description:** When protocol fees are updated, the new fee rate retroactively applies
to previously earned but unclaimed fees. Users who earned fees at 5% are suddenly
charged 10% on their existing earnings.

**Pattern:**
```move
// VULNERABLE — fee change applies retroactively to unclaimed rewards
public fun set_protocol_fee(admin: &AdminCap, vault: &mut Vault, new_fee: u64) {
    // Changes fee immediately — unclaimed rewards now charged at new rate
    vault.protocol_fee_bps = new_fee;
}

// SAFE — harvest existing rewards before changing fee
public fun set_protocol_fee(admin: &AdminCap, vault: &mut Vault, new_fee: u64) {
    // Collect all pending fees at current rate first
    harvest_all_pending_fees(vault);
    // Then update fee rate for future earnings only
    vault.protocol_fee_bps = new_fee;
}
```

**Check:**
1. When fees are updated, are existing unclaimed rewards settled first?
2. Can a fee increase be applied retroactively to disadvantage users?
3. Is there a timelock on fee changes to allow users to claim before change?

---

## Auction / CLM Verification Checklist

- [ ] Self-bidding prevented in auction mechanisms (DEFI-67)
- [ ] Minimum auction duration enforced (DEFI-68)
- [ ] Auction timestamp comparisons use correct operator (`>` vs `>=`) (DEFI-69)
- [ ] All liquidity deployment functions check TWAP before execution (DEFI-70)
- [ ] TWAP deviation and window parameters have enforced bounds (DEFI-71)
- [ ] Rounding dust from tick math is tracked and recoverable (DEFI-72)
- [ ] Fee changes do not apply retroactively to unclaimed rewards (DEFI-73)
