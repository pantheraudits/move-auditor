# DeFi Slippage & MEV — Move

Deep-dive patterns for slippage protection and MEV vulnerabilities in Move DeFi protocols.
These apply to all swap, AMM, and liquidity operations on Sui and Aptos.

---

## DEFI-43 — Zero or Missing `min_amount_out`

**Description:** Swap functions that accept no minimum output parameter, or default it
to zero, allow sandwich attacks to extract nearly 100% of the swap value. This is the
single most common MEV vulnerability in DeFi.

**Pattern:**
```move
// VULNERABLE — no min_amount_out parameter at all
public entry fun swap<CoinIn, CoinOut>(
    pool: &mut Pool<CoinIn, CoinOut>,
    coin_in: Coin<CoinIn>,
    ctx: &mut TxContext
) {
    let coin_out = do_swap(pool, coin_in);
    // No check on coin_out value — sandwich extracts all value
    transfer::public_transfer(coin_out, tx_context::sender(ctx));
}

// SAFE — user specifies and enforces minimum output
public entry fun swap<CoinIn, CoinOut>(
    pool: &mut Pool<CoinIn, CoinOut>,
    coin_in: Coin<CoinIn>,
    min_amount_out: u64,
    ctx: &mut TxContext
) {
    let coin_out = do_swap(pool, coin_in);
    assert!(coin::value(&coin_out) >= min_amount_out, E_SLIPPAGE_EXCEEDED);
    transfer::public_transfer(coin_out, tx_context::sender(ctx));
}
```

**Check:**
1. Every swap/exchange entry function must have a `min_amount_out` parameter
2. Grep: `fun swap`, `fun exchange`, `fun trade` — verify slippage param exists
3. Check that `min_amount_out = 0` is rejected or warned against in documentation
4. Verify the assertion happens AFTER the swap, comparing actual output
5. Cross-ref: DEFI-07

---

## DEFI-44 — No Deadline Parameter

**Description:** Transactions without a deadline can be held by validators or
sequencers and executed at a later time when market conditions have changed
unfavorably. Unlike EVM's `block.timestamp`, Move has no implicit tx deadline.

**Pattern:**
```move
// VULNERABLE — no deadline, tx can be delayed indefinitely
public entry fun swap<A, B>(
    pool: &mut Pool<A, B>,
    coin_in: Coin<A>,
    min_out: u64,
    ctx: &mut TxContext
) {
    // Even with min_out, a delayed tx might execute when min_out
    // is far below market price — user gets worst acceptable price
    let out = do_swap(pool, coin_in);
    assert!(coin::value(&out) >= min_out, E_SLIPPAGE);
    transfer::public_transfer(out, tx_context::sender(ctx));
}

// SAFE — enforce deadline (Sui)
public entry fun swap<A, B>(
    pool: &mut Pool<A, B>,
    coin_in: Coin<A>,
    min_out: u64,
    deadline_ms: u64,
    clock: &Clock,
    ctx: &mut TxContext
) {
    assert!(clock::timestamp_ms(clock) <= deadline_ms, E_EXPIRED);
    let out = do_swap(pool, coin_in);
    assert!(coin::value(&out) >= min_out, E_SLIPPAGE);
    transfer::public_transfer(out, tx_context::sender(ctx));
}
```

**Check:**
1. All time-sensitive operations (swaps, liquidations, auctions) should have a deadline
2. On Sui: deadline checked against `clock::timestamp_ms(clock)`
3. On Aptos: deadline checked against `timestamp::now_seconds()`
4. Verify deadline is checked at the START of the function, not after state changes

---

## DEFI-45 — Hardcoded / Fixed Slippage Tolerance

**Description:** A hardcoded slippage tolerance (e.g., `const SLIPPAGE_BPS: u64 = 500`)
prevents users from setting tighter protection. During high volatility, the fixed tolerance
may be too loose (sandwich profitable). During low liquidity, it may be too tight (tx reverts,
funds stuck).

**Pattern:**
```move
// VULNERABLE — hardcoded 5% slippage
const SLIPPAGE_BPS: u64 = 500;

public fun rebalance(pool: &mut Pool, amount: u64) {
    let expected = calculate_output(pool, amount);
    let min_out = expected * (10000 - SLIPPAGE_BPS) / 10000; // always 5%
    let out = do_swap(pool, amount);
    assert!(coin::value(&out) >= min_out, E_SLIPPAGE);
    // 5% is too loose for stable pairs, too tight during volatility
}

// SAFE — user-provided or per-operation slippage
public fun rebalance(pool: &mut Pool, amount: u64, max_slippage_bps: u64) {
    assert!(max_slippage_bps <= MAX_ALLOWED_SLIPPAGE, E_SLIPPAGE_TOO_HIGH);
    let expected = calculate_output(pool, amount);
    let min_out = expected * (10000 - max_slippage_bps) / 10000;
    let out = do_swap(pool, amount);
    assert!(coin::value(&out) >= min_out, E_SLIPPAGE);
}
```

**Check:**
1. Grep: `const.*SLIPPAGE`, `const.*SLIP` — flag any hardcoded slippage values
2. Admin/keeper functions using protocol funds are especially vulnerable
3. Verify slippage cannot be set to 100% (effectively zero protection)
4. Check if hardcoded slippage can cause withdrawal failures during volatility

---

## DEFI-46 — On-Chain Self-Referential Slippage Calculation

**Description:** Calculating `min_amount_out` from the same pool state that will execute
the swap. An attacker manipulates pool state first, then the slippage calculation reflects
the manipulated state — offering zero protection.

**Pattern:**
```move
// VULNERABLE — slippage calculated from manipulable on-chain state
public fun swap_with_auto_slippage<A, B>(pool: &mut Pool<A, B>, coin_in: Coin<A>) {
    let amount_in = coin::value(&coin_in);
    // Attacker front-runs: manipulates pool reserves
    // Now quote() returns the manipulated price as "expected"
    let expected_out = quote(pool, amount_in);
    let min_out = expected_out * 95 / 100; // 5% of manipulated price = no protection
    let out = do_swap(pool, coin_in);
    assert!(coin::value(&out) >= min_out, E_SLIPPAGE);
}

// SAFE — min_amount_out comes from off-chain calculation
public fun swap<A, B>(
    pool: &mut Pool<A, B>,
    coin_in: Coin<A>,
    min_amount_out: u64,  // calculated off-chain from TWAP or external oracle
    ctx: &mut TxContext
) {
    let out = do_swap(pool, coin_in);
    assert!(coin::value(&out) >= min_amount_out, E_SLIPPAGE);
    transfer::public_transfer(out, tx_context::sender(ctx));
}
```

**Check:**
1. Identify any function that both queries a price AND executes against the same pool
2. `min_amount_out` must come from the user (off-chain) or a separate oracle (TWAP)
3. Any "auto-slippage" feature that reads from the pool being swapped is vulnerable
4. Cross-ref: DEFI-01

---

## DEFI-47 — LP Operation Slippage (Add/Remove Liquidity)

**Description:** Slippage protection implemented for swaps but missing for `add_liquidity`
and `remove_liquidity`. LP tokens minted or assets received can be sandwiched just like
swaps. Attacker skews the pool ratio before the LP operation.

**Pattern:**
```move
// VULNERABLE — add_liquidity has no slippage protection
public entry fun add_liquidity<A, B>(
    pool: &mut Pool<A, B>,
    coin_a: Coin<A>,
    coin_b: Coin<B>,
    ctx: &mut TxContext
) {
    let lp_tokens = mint_lp(pool, coin_a, coin_b);
    // No check on lp_tokens value — attacker skews pool to reduce LP minted
    transfer::public_transfer(lp_tokens, tx_context::sender(ctx));
}

// SAFE — enforce minimum LP tokens minted
public entry fun add_liquidity<A, B>(
    pool: &mut Pool<A, B>,
    coin_a: Coin<A>,
    coin_b: Coin<B>,
    min_lp_out: u64,
    ctx: &mut TxContext
) {
    let lp_tokens = mint_lp(pool, coin_a, coin_b);
    assert!(coin::value(&lp_tokens) >= min_lp_out, E_SLIPPAGE_LP);
    transfer::public_transfer(lp_tokens, tx_context::sender(ctx));
}
```

**Check:**
1. All `add_liquidity` functions must have `min_lp_out` parameter
2. All `remove_liquidity` functions must have `min_amount_a` and `min_amount_b` parameters
3. Single-sided liquidity operations are especially vulnerable — check proportional deposit
4. Cross-ref: DEFI-03

---

## DEFI-48 — Token vs USD Slippage Confusion

**Description:** Slippage set in token terms when the real risk is USD value, or vice versa.
In multi-hop swaps, intermediate token amounts may look fine but the final USD value is
significantly lower due to price movements across the hops.

**Pattern:**
```move
// VULNERABLE — slippage on intermediate hop, not final output
public fun multi_hop_swap(
    pool_ab: &mut Pool<A, B>,
    pool_bc: &mut Pool<B, C>,
    coin_a: Coin<A>,
    min_b: u64,  // only protects first hop
    ctx: &mut TxContext
) {
    let coin_b = swap(pool_ab, coin_a);
    assert!(coin::value(&coin_b) >= min_b, E_SLIPPAGE);
    let coin_c = swap(pool_bc, coin_b);
    // No slippage check on final output coin_c!
    transfer::public_transfer(coin_c, tx_context::sender(ctx));
}

// SAFE — slippage on final output
public fun multi_hop_swap(
    pool_ab: &mut Pool<A, B>,
    pool_bc: &mut Pool<B, C>,
    coin_a: Coin<A>,
    min_final_out: u64,  // protects final output
    ctx: &mut TxContext
) {
    let coin_b = swap(pool_ab, coin_a);
    let coin_c = swap(pool_bc, coin_b);
    assert!(coin::value(&coin_c) >= min_final_out, E_SLIPPAGE);
    transfer::public_transfer(coin_c, tx_context::sender(ctx));
}
```

**Check:**
1. In multi-hop swaps, slippage must protect the FINAL output, not intermediates
2. Check if intermediate slippage checks give false sense of security
3. For USD-denominated protocols, verify slippage is in USD value terms

---

## DEFI-49 — PTB Composability Sandwich (Sui-Specific)

**Description:** Sui's Programmable Transaction Blocks (PTBs) allow composing multiple
operations atomically. While PTBs make DeFi more composable, they also enable
sophisticated sandwich attacks within a single transaction block by validators.

**Pattern:**
```move
// CONTEXT — Sui PTB enables atomic multi-step operations
// A validator can construct a PTB that:
// 1. Swaps large amount in Pool to move price (front-run)
// 2. Includes victim's swap transaction
// 3. Swaps back to capture profit (back-run)
// All within the SAME transaction block

// VULNERABLE — entry function allows arbitrary composition
public entry fun swap_and_deposit<A, B>(
    pool: &mut Pool<A, B>,
    vault: &mut Vault<B>,
    coin_a: Coin<A>,
    ctx: &mut TxContext
) {
    let coin_b = do_swap(pool, coin_a);
    // Swap output deposited without slippage check
    deposit_to_vault(vault, coin_b, ctx);
}

// SAFE — enforce slippage at each composable boundary
public entry fun swap_and_deposit<A, B>(
    pool: &mut Pool<A, B>,
    vault: &mut Vault<B>,
    coin_a: Coin<A>,
    min_swap_out: u64,
    min_vault_shares: u64,
    deadline_ms: u64,
    clock: &Clock,
    ctx: &mut TxContext
) {
    assert!(clock::timestamp_ms(clock) <= deadline_ms, E_EXPIRED);
    let coin_b = do_swap(pool, coin_a);
    assert!(coin::value(&coin_b) >= min_swap_out, E_SLIPPAGE);
    let shares = deposit_to_vault(vault, coin_b, ctx);
    assert!(shares >= min_vault_shares, E_SLIPPAGE_VAULT);
}
```

**Check:**
1. On Sui: every composable entry function must enforce its own slippage protection
2. Do not rely on the "caller will check" — PTBs can bypass intermediate checks
3. Verify that shared object mutations in multi-step PTBs cannot be front-run by validators
4. Check if `public entry` functions expose unprotected intermediate states
5. Cross-ref: SUI-02, SUI-11

---

## Slippage / MEV Verification Checklist

- [ ] All swap entry functions have `min_amount_out` parameter (DEFI-43)
- [ ] Time-sensitive operations enforce a deadline parameter (DEFI-44)
- [ ] No hardcoded slippage constants used for user-facing operations (DEFI-45)
- [ ] Slippage calculations use off-chain values, not same-pool queries (DEFI-46)
- [ ] `add_liquidity` and `remove_liquidity` have slippage protection (DEFI-47)
- [ ] Multi-hop swaps protect final output, not just intermediates (DEFI-48)
- [ ] On Sui: PTB-composable functions enforce slippage at each boundary (DEFI-49)
