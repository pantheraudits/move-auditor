# DeFi Oracle Vulnerability Patterns (DEFI-17 to DEFI-24)

Oracle integrations are a critical attack surface in Move DeFi protocols.
Pyth and Switchboard are the primary providers on Sui and Aptos.

---

## DEFI-17 — Stale Price Data

**Description:** Oracle price consumed without checking `publish_time` (Pyth) or
`latest_round_timestamp` (Switchboard) against a max staleness threshold, enabling
arbitrage against outdated valuations.

**Pattern:**
```move
// VULNERABLE — no staleness check, price could be hours old
public fun get_token_price(price_info: &PriceInfoObject): u64 {
    (pyth::price::get_price(&pyth::price_info::get_price(price_info)) as u64)
}

// SAFE — enforce maximum staleness
const MAX_STALE_SECONDS: u64 = 60;
const E_STALE_PRICE: u64 = 1001;

public fun get_token_price_safe(price_info: &PriceInfoObject, clock: &Clock): u64 {
    let price = pyth::price_info::get_price(price_info);
    assert!(clock::timestamp_ms(clock) / 1000 - pyth::price::get_publish_time(&price) < MAX_STALE_SECONDS, E_STALE_PRICE);
    (pyth::price::get_price(&price) as u64)
}
```

**Check:**
1. Every `get_price` call must have a `publish_time` / `timestamp` comparison nearby
2. Grep: `get_price` without a nearby `publish_time` or `timestamp` assertion
3. Cross-ref: DEFI-01

---

## DEFI-18 — Same Staleness Threshold for Different Feeds

**Description:** One `MAX_STALE` constant for all feeds. Volatile assets (BTC, ETH)
need tight windows (30-60 s), stablecoins need wider ones (3600 s). A universal
threshold is either too loose or too tight.

**Pattern:**
```move
// VULNERABLE — one constant for all feeds (too loose for BTC, maybe fine for USDC)
const MAX_STALE: u64 = 3600;

public fun check_price(price_info: &PriceInfoObject, clock: &Clock): u64 {
    let price = pyth::price_info::get_price(price_info);
    assert!(clock::timestamp_ms(clock) / 1000 - pyth::price::get_publish_time(&price) < MAX_STALE, E_STALE_PRICE);
    (pyth::price::get_price(&price) as u64)
}

// SAFE — per-feed staleness via Table<ID, u64>
struct OracleConfig has key, store { id: UID, staleness: Table<ID, u64> }

public fun check_price_safe(
    config: &OracleConfig, feed_id: ID, price_info: &PriceInfoObject, clock: &Clock,
): u64 {
    let price = pyth::price_info::get_price(price_info);
    let max_stale = *table::borrow(&config.staleness, feed_id);
    assert!(clock::timestamp_ms(clock) / 1000 - pyth::price::get_publish_time(&price) < max_stale, E_STALE_PRICE);
    (pyth::price::get_price(&price) as u64)
}
```

**Check:**
1. Look for a single `MAX_STALE` / `MAX_STALENESS` constant used across multiple feed reads
2. Grep: `const MAX_STALE` or `const STALENESS` — check if one constant or a per-feed config
3. Cross-ref: DEFI-17

---

## DEFI-19 — Oracle Decimal/Exponent Mismatch

**Description:** Pyth returns price as `i64` with `i32` exponent (price=12345,
expo=-2 = $123.45). Ignoring the exponent causes 10^N magnitude errors.

**Pattern:**
```move
// VULNERABLE — raw price without applying exponent
public fun value_in_usd(amount: u64, price_info: &PriceInfoObject): u64 {
    let price = pyth::price_info::get_price(price_info);
    // price=2950000, expo=-5 => real=$29.50, but treats 2950000 as dollar price
    amount * (pyth::price::get_price(&price) as u64)
}

// SAFE — normalize using exponent: result = amount * price * 10^(target_decimals + expo)
const TARGET_DECIMALS: u8 = 8;

public fun value_in_usd_safe(amount: u64, amt_dec: u8, price_info: &PriceInfoObject): u64 {
    let price = pyth::price_info::get_price(price_info);
    let raw = pyth::price::get_price(&price);
    assert!(raw > 0, E_NEGATIVE_PRICE);
    let expo = pyth::price::get_expo(&price); // e.g., -5
    let adj = (TARGET_DECIMALS as i32) - (amt_dec as i32) + expo;
    if (adj >= 0) { amount * (raw as u64) * math::pow(10, (adj as u8)) }
    else { amount * (raw as u64) / math::pow(10, ((-adj) as u8)) }
}
```

**Check:**
1. Every `get_price()` usage must have a corresponding `get_expo()` call
2. Grep: `get_price` without `get_expo` in the same function
3. Cross-ref: common-move.md 8.4

---

## DEFI-20 — Wrong Price Feed ID

**Description:** Pyth feed IDs are chain-specific (Sui: `PriceInfoObject` ID,
Aptos: 32-byte address). Testnet IDs differ from mainnet. Wrong feed ID prices
assets with entirely incorrect data.

**Pattern:**
```move
// VULNERABLE (Sui) — no verification of feed identity
public fun get_btc_price(price_info: &PriceInfoObject): u64 {
    // Caller can pass ANY PriceInfoObject — could be ETH/USD, not BTC/USD
    let price = pyth::price_info::get_price(price_info);
    (pyth::price::get_price(&price) as u64)
}

// VULNERABLE (Aptos) — hardcoded feed without validation
const BTC_FEED: vector<u8> = x"aabbccdd"; // could be testnet-only

public fun get_btc_price_aptos(): u64 {
    let price = pyth::get_price(BTC_FEED, timestamp::now_seconds());
    (pyth::price::get_price(&price) as u64)
}

// SAFE — registry validates feed identity at runtime
struct FeedRegistry has key, store { id: UID, feeds: Table<String, ID> }
const E_WRONG_FEED: u64 = 3001;

public fun get_price_checked(
    reg: &FeedRegistry, asset: String, price_info: &PriceInfoObject, clock: &Clock,
): u64 {
    assert!(object::id(price_info) == *table::borrow(&reg.feeds, asset), E_WRONG_FEED);
    let price = pyth::price_info::get_price(price_info);
    assert!(clock::timestamp_ms(clock) / 1000 - pyth::price::get_publish_time(&price) < 60, E_STALE_PRICE);
    (pyth::price::get_price(&price) as u64)
}
```

**Check:**
1. Look for hardcoded hex addresses or object IDs used as price feed identifiers
2. Grep: `const.*FEED` or `@0x` near oracle code — check testnet vs mainnet configs
3. Cross-ref: DEFI-17, SUI-01 / APT-01

---

## DEFI-21 — Depeg Events Not Handled

**Description:** Protocol assumes wrapped/pegged asset equals underlying (wBTC=BTC,
USDC=$1). Depeg breaks this, causing incorrect valuations and exploitable arbitrage.

**Pattern:**
```move
// VULNERABLE — uses BTC/USD price for wBTC, ignores depeg
public fun wbtc_collateral_value(wbtc_amount: u64, btc_usd_info: &PriceInfoObject): u64 {
    let price = pyth::price_info::get_price(btc_usd_info);
    wbtc_amount * (pyth::price::get_price(&price) as u64) // assumes wBTC == BTC
}

// SAFE — use dedicated wBTC/USD feed + depeg circuit breaker
const MAX_DEPEG_BPS: u64 = 200; const BPS_BASE: u64 = 10000;
const E_DEPEG_DETECTED: u64 = 4001;

public fun wbtc_collateral_value_safe(
    wbtc_amount: u64, wbtc_usd_info: &PriceInfoObject, btc_usd_info: &PriceInfoObject,
): u64 {
    let wbtc_usd = (pyth::price::get_price(&pyth::price_info::get_price(wbtc_usd_info)) as u64);
    let btc_usd = (pyth::price::get_price(&pyth::price_info::get_price(btc_usd_info)) as u64);
    let ratio_bps = wbtc_usd * BPS_BASE / btc_usd;
    let dev = if (ratio_bps > BPS_BASE) { ratio_bps - BPS_BASE } else { BPS_BASE - ratio_bps };
    assert!(dev <= MAX_DEPEG_BPS, E_DEPEG_DETECTED);
    wbtc_amount * wbtc_usd
}
```

**Check:**
1. Look for wrapped/pegged tokens valued using the underlying token's oracle feed
2. Grep: `wbtc.*btc_price` or `steth.*eth_price` — wrapped asset using unwrapped feed
3. Cross-ref: DEFI-22, DEFI-01

---

## DEFI-22 — Oracle Min/Max Price Bounds

**Description:** Oracle returns extreme values (0, negative, MAX_U64) during outages.
Zero prices enable infinite borrowing; extreme prices trigger mass liquidations.

**Pattern:**
```move
// VULNERABLE — no bounds check; price could be 0 (div-by-zero) or MAX_U64 (overflow)
public fun get_collateral_ratio(debt: u64, collateral: u64, price_info: &PriceInfoObject): u64 {
    let val = (pyth::price::get_price(&pyth::price_info::get_price(price_info)) as u64);
    collateral * val / debt
}

// SAFE — enforce min/max bounds after oracle read
const MIN_PRICE: u64 = 1; const MAX_PRICE: u64 = 1_000_000_000_000;
const E_PRICE_OUT_OF_BOUNDS: u64 = 5001;

public fun get_price_bounded(price_info: &PriceInfoObject, clock: &Clock): u64 {
    let price = pyth::price_info::get_price(price_info);
    assert!(clock::timestamp_ms(clock) / 1000 - pyth::price::get_publish_time(&price) < 60, E_STALE_PRICE);
    let raw = pyth::price::get_price(&price);
    assert!(raw > 0, E_NEGATIVE_PRICE);
    let val = (raw as u64);
    assert!(val >= MIN_PRICE && val <= MAX_PRICE, E_PRICE_OUT_OF_BOUNDS);
    val
}
```

**Check:**
1. Look for oracle reads flowing directly into arithmetic with no `assert!` on bounds
2. Grep: `get_price` followed by `*` or `/` without an intermediate bounds check
3. Cross-ref: DEFI-17, common-move.md 8.1 (overflow/underflow)

---

## DEFI-23 — Price Direction Confusion

**Description:** Using TOKEN_A/TOKEN_B price where TOKEN_B/TOKEN_A was needed
(e.g., ETH/USD=3000 used as USD/ETH). Calculations off by price squared.

**Pattern:**
```move
// VULNERABLE — inverted price direction
public fun eth_needed_for_usd(usd_amount: u64, eth_usd_info: &PriceInfoObject): u64 {
    let eth_per_usd = (pyth::price::get_price(&pyth::price_info::get_price(eth_usd_info)) as u64);
    // BUG: oracle returns usd_per_eth (3000), not eth_per_usd
    usd_amount * eth_per_usd // returns usd * 3000 instead of usd / 3000
}

// SAFE — ETH/USD = USD per 1 ETH. USD->ETH: divide. ETH->USD: multiply.
const PRECISION: u64 = 100_000_000;

public fun eth_needed_for_usd_safe(
    usd_amount: u64, eth_usd_price_info: &PriceInfoObject, clock: &Clock,
): u64 {
    let price = pyth::price_info::get_price(eth_usd_price_info);
    assert!(clock::timestamp_ms(clock) / 1000 - pyth::price::get_publish_time(&price) < 60, E_STALE_PRICE);
    let usd_per_eth = (pyth::price::get_price(&price) as u64);
    assert!(usd_per_eth > 0, E_NEGATIVE_PRICE);
    usd_amount * PRECISION / usd_per_eth // divide to go USD -> ETH
}

/// Cross-rate: BTC in ETH = BTC_USD / ETH_USD
public fun cross_rate(btc_info: &PriceInfoObject, eth_info: &PriceInfoObject): u64 {
    let btc_usd = (pyth::price::get_price(&pyth::price_info::get_price(btc_info)) as u64);
    let eth_usd = (pyth::price::get_price(&pyth::price_info::get_price(eth_info)) as u64);
    btc_usd * PRECISION / eth_usd
}
```

**Check:**
1. Look for oracle prices used in multiplication where division was needed, or vice versa
2. Grep: variable names containing `per` — verify direction matches oracle feed definition
3. Cross-ref: DEFI-19, common-move.md 8.4

---

## DEFI-24 — Missing Circuit Breakers

**Description:** No deviation check between consecutive oracle updates. A sudden
50x spike triggers mass liquidations or unbounded borrowing immediately.

**Pattern:**
```move
// VULNERABLE — blindly accepts any price, even 100x jumps
struct PriceState has key, store { id: UID, current_price: u64 }

public fun update_price(state: &mut PriceState, price_info: &PriceInfoObject) {
    state.current_price = (pyth::price::get_price(
        &pyth::price_info::get_price(price_info)) as u64); // no deviation check
}

// SAFE — circuit breaker pauses on abnormal deviation
const MAX_DEV_BPS: u64 = 1500; const BPS: u64 = 10000; // 15% max
const E_CIRCUIT_BREAKER: u64 = 6001;

struct PriceState has key, store { id: UID, current_price: u64, is_paused: bool }

public fun update_price_safe(state: &mut PriceState, price_info: &PriceInfoObject, clock: &Clock) {
    assert!(!state.is_paused, E_CIRCUIT_BREAKER);
    let price = pyth::price_info::get_price(price_info);
    assert!(clock::timestamp_ms(clock) / 1000 - pyth::price::get_publish_time(&price) < 60, E_STALE_PRICE);
    let new_price = (pyth::price::get_price(&price) as u64);
    assert!(new_price > 0, E_NEGATIVE_PRICE);
    if (state.current_price > 0) {
        let dev = if (new_price > state.current_price) {
            (new_price - state.current_price) * BPS / state.current_price
        } else { (state.current_price - new_price) * BPS / state.current_price };
        if (dev > MAX_DEV_BPS) {
            state.is_paused = true;
            event::emit(CircuitBreakerTripped { last_price: state.current_price, new_price, deviation_bps: dev });
            abort E_CIRCUIT_BREAKER
        };
    };
    state.current_price = new_price;
}

public fun unpause(state: &mut PriceState, _admin: &AdminCap) { state.is_paused = false; }
```

**Check:**
1. Look for price storage that overwrites `last_price` with no deviation comparison
2. Grep: `current_price =` or `last_price =` near oracle reads — verify deviation check before assignment
3. Cross-ref: DEFI-22, DEFI-17

---

## Oracle Integration Verification Checklist

- [ ] **Staleness:** Every oracle read checks `publish_time` / `latest_round_timestamp` against max age (DEFI-17)
- [ ] **Per-feed staleness:** Volatile assets use tighter thresholds than stablecoins (DEFI-18)
- [ ] **Exponent handling:** Price exponent correctly applied when normalizing to protocol precision (DEFI-19)
- [ ] **Feed identity:** Feed IDs validated against on-chain registry; testnet vs mainnet verified (DEFI-20)
- [ ] **Depeg awareness:** Wrapped/pegged assets use own price feeds or have depeg breakers (DEFI-21)
- [ ] **Bounds validation:** Prices checked against min/max bounds before arithmetic (DEFI-22)
- [ ] **Price direction:** Quote direction (A/B vs B/A) documented and correctly applied (DEFI-23)
- [ ] **Circuit breakers:** Abnormal deviations trigger pause rather than immediate execution (DEFI-24)
