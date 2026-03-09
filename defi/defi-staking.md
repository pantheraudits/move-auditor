# DeFi Staking — Vulnerability Patterns

Staking-specific vulnerability patterns for Move smart contracts. Load when auditing
protocols using `stake`, `unstake`, `reward_per_share`, `accumulator`, or `farming` logic.

---

## DEFI-11 — First Depositor Share Theft

**Description:** The first depositor manipulates the share-to-asset ratio to steal from
subsequent depositors. Attacker deposits 1 unit (1 share), donates tokens directly to
inflate price-per-share. Next depositor's shares round to 0, attacker redeems all assets.

**Pattern:**
```move
// VULNERABLE — no minimum initial shares, no dead shares burned
public fun deposit<T>(pool: &mut Pool<T>, coin: Coin<T>): u64 {
    let deposit_amount = coin::value(&coin);
    let total_balance = balance::value(&pool.balance);
    let shares = if (pool.total_shares == 0) {
        deposit_amount  // first depositor gets 1:1 shares
    } else {
        // Attack: total_balance inflated via direct donation
        // deposit_amount=5000, total_shares=1, total_balance=10000
        // shares = 5000 * 1 / 10000 = 0 -> depositor gets ZERO shares
        (deposit_amount * pool.total_shares) / total_balance
    };
    balance::join(&mut pool.balance, coin::into_balance(coin));
    pool.total_shares = pool.total_shares + shares;
    shares
}

// SAFE — burn minimum initial shares to anchor the ratio
public fun deposit<T>(pool: &mut Pool<T>, coin: Coin<T>): u64 {
    let deposit_amount = coin::value(&coin);
    let total_balance = balance::value(&pool.balance);
    let shares = if (pool.total_shares == 0) {
        assert!(deposit_amount > MIN_INITIAL_SHARES, E_INSUFFICIENT_INITIAL);
        pool.total_shares = MIN_INITIAL_SHARES; // burn dead shares
        deposit_amount - MIN_INITIAL_SHARES
    } else {
        (deposit_amount * pool.total_shares) / total_balance
    };
    assert!(shares > 0, E_ZERO_SHARES);
    balance::join(&mut pool.balance, coin::into_balance(coin));
    pool.total_shares = pool.total_shares + shares;
    shares
}
```

**Check:**
1. Is the pool's first deposit protected by burning minimum dead shares or enforcing a minimum deposit?
2. Can an attacker call `balance::join` directly to inflate the ratio?
3. Does the share calculation guard against returning 0 shares?
4. Cross-ref: DEFI-03

---

## DEFI-12 — Reward Dilution via Direct Transfer

**Description:** Sending reward tokens directly to a staking pool's balance bypasses
the reward accumulator update. The balance increases but `reward_per_share` is never
updated, causing rewards to be distributed incorrectly or silently lost.

**Pattern:**
```move
// VULNERABLE — uses pool balance for reward calculation
public fun update_rewards<T>(pool: &mut StakePool<T>) {
    let current_balance = balance::value(&pool.balance);
    // BUG: current_balance includes directly deposited tokens
    let new_rewards = (current_balance as u128) - (pool.total_staked as u128);
    if (pool.total_staked > 0) {
        pool.reward_per_share = pool.reward_per_share
            + new_rewards / (pool.total_staked as u128);
    };
}

// SAFE — separate staked/reward balances, explicit reward injection
public fun add_rewards<T>(pool: &mut StakePool<T>, reward_coin: Coin<T>) {
    let reward_amount = coin::value(&reward_coin);
    if (pool.total_staked > 0) {
        pool.reward_per_share = pool.reward_per_share
            + ((reward_amount as u128) * PRECISION) / (pool.total_staked as u128);
    };
    pool.distributed_rewards = pool.distributed_rewards + reward_amount;
    balance::join(&mut pool.reward_balance, coin::into_balance(reward_coin));
}
```

**Check:**
1. Does the protocol use `balance::value(&pool.balance)` to derive reward amounts?
2. Are staked funds and reward funds stored in separate `Balance` fields?
3. Can anyone call `balance::join` on the pool outside the intended deposit flow?
4. On Sui: can a PTB compose a direct deposit with a claim?
5. Cross-ref: DEFI-05

---

## DEFI-13 — Precision Loss in Reward Accumulator

**Description:** Move's `u64` (max ~1.8e19) and `u128` (max ~3.4e38) are smaller than
Solidity's `uint256`. When `total_staked` is large relative to `reward_amount`, the
`reward_per_share` increment rounds to 0, silently destroying rewards.

**Pattern:**
```move
// VULNERABLE — u64 arithmetic, no precision scaling
public fun update_reward_index(pool: &mut Pool, reward_amount: u64) {
    if (pool.total_staked == 0) return;
    // reward_amount=999, total_staked=1_000_000 -> increment = 0
    pool.reward_per_share = pool.reward_per_share
        + reward_amount / pool.total_staked;
}

// SAFE — multiply before divide, u128 intermediate, large PRECISION
const PRECISION: u128 = 1_000_000_000_000; // 1e12

public fun update_reward_index(pool: &mut Pool, reward_amount: u64) {
    if (pool.total_staked == 0) return;
    pool.reward_per_share = pool.reward_per_share
        + ((reward_amount as u128) * PRECISION) / (pool.total_staked as u128);
}

public fun pending_reward(pool: &Pool, user_staked: u64, user_debt: u128): u64 {
    let raw = ((user_staked as u128) * pool.reward_per_share) / PRECISION;
    ((raw - user_debt) as u64)
}
```

**Check:**
1. Is the reward accumulator stored as `u128`? `u64` overflows or rounds to 0 easily
2. Does the update formula multiply by PRECISION (>= 1e12) before dividing?
3. Does `pending_reward` correctly divide by PRECISION when computing payouts?
4. Cross-ref: common-move.md 2.2

---

## DEFI-14 — Flash Deposit/Withdraw Griefing

**Description:** Attacker performs a large flash deposit to dilute pending rewards, claims
a disproportionate share, then immediately withdraws. On Sui, PTBs enable
stake + claim + unstake in a single transaction block.

**Pattern:**
```move
// VULNERABLE — no minimum stake duration, rewards claimable immediately
struct UserStake has key, store {
    id: UID,
    amount: u64,
    reward_debt: u128,
    // No timestamp — no duration enforcement
}

public fun unstake<T>(pool: &mut Pool<T>, user: UserStake, ctx: &mut TxContext): Coin<T> {
    let UserStake { id, amount, reward_debt: _ } = user;
    object::delete(id);
    pool.total_staked = pool.total_staked - amount;
    coin::from_balance(balance::split(&mut pool.staked, amount), ctx)
}

// SAFE — enforce minimum stake duration
struct UserStake has key, store {
    id: UID,
    amount: u64,
    reward_debt: u128,
    stake_time_ms: u64,
}

public fun unstake<T>(
    pool: &mut Pool<T>, user: UserStake, clock: &Clock, ctx: &mut TxContext
): Coin<T> {
    let UserStake { id, amount, reward_debt: _, stake_time_ms } = user;
    let elapsed = clock::timestamp_ms(clock) - stake_time_ms;
    assert!(elapsed >= MIN_STAKE_DURATION_MS, E_STAKE_TOO_SHORT); // e.g., 24h
    object::delete(id);
    pool.total_staked = pool.total_staked - amount;
    coin::from_balance(balance::split(&mut pool.staked, amount), ctx)
}
```

**Check:**
1. Can `stake()` + `claim()` + `unstake()` be called in the same transaction (PTB on Sui)?
2. Is there a minimum stake duration enforced via on-chain timestamp?
3. Does reward distribution use time-weighted calculations that resist single-block manipulation?
4. Cross-ref: SUI-02, common-move.md 10.2

---

## DEFI-15 — Stale Reward Index After Distribution

**Description:** Adding new rewards without updating `reward_per_share` first causes
stale calculations. The admin `add_rewards()` function omits the index update call
that every other state-modifying function includes.

**Pattern:**
```move
// VULNERABLE — add_rewards does not update reward index
public fun stake<T>(pool: &mut Pool<T>, clock: &Clock, amount: u64) {
    update_reward_index(pool, clock); // correctly updates
    pool.total_staked = pool.total_staked + amount;
}

public fun add_rewards<T>(pool: &mut Pool<T>, reward_coin: Coin<T>, new_rate: u64) {
    // Missing: update_reward_index(pool, clock);
    // Rewards accrued at old rate since last_update_time are lost
    balance::join(&mut pool.reward_balance, coin::into_balance(reward_coin));
    pool.reward_rate = new_rate;  // rate change applied retroactively
}

// SAFE — always update index before modifying distribution parameters
public fun add_rewards<T>(
    pool: &mut Pool<T>, reward_coin: Coin<T>, new_rate: u64, clock: &Clock
) {
    update_reward_index(pool, clock); // settle accrued rewards at old rate
    balance::join(&mut pool.reward_balance, coin::into_balance(reward_coin));
    pool.reward_rate = new_rate;      // now safe to change rate
}
```

**Check:**
1. List every function that modifies `reward_rate`, `total_staked`, or distribution parameters
2. Does each call `update_reward_index()` before the modification?
3. Admin functions are the most common offenders — check `add_rewards()`, `set_reward_rate()`
4. If admin function lacks a `Clock` parameter, it physically cannot call the update
5. Cross-ref: DEFI-05

---

## DEFI-16 — Balance Caching Mismatch

**Description:** A cached balance value diverges from actual on-chain balance during
transaction execution. On Sui, `balance::value()` on a shared object can change between
PTB steps. On Aptos, `borrow_global` returns a snapshot that may differ after subsequent
operations within the same transaction.

**Pattern:**
```move
// VULNERABLE — reads balance at start, uses stale cached value after operations
public fun compound_and_withdraw<T>(vault: &mut Vault<T>, amount: u64, ctx: &mut TxContext): Coin<T> {
    let cached_balance = balance::value(&vault.balance); // cache
    // Operation 1: compound pending rewards (modifies vault.balance)
    let reward = vault.pending_rewards;
    vault.pending_rewards = 0;
    // BUG: cached_balance is stale — doesn't include compounded rewards
    let user_share = (amount * 10000) / cached_balance; // inflated share
    coin::from_balance(balance::split(&mut vault.balance, amount), ctx)
}

// SAFE — re-read balance after any operation that modifies it
public fun compound_and_withdraw<T>(vault: &mut Vault<T>, amount: u64, ctx: &mut TxContext): Coin<T> {
    let reward = vault.pending_rewards;
    vault.pending_rewards = 0;
    // Re-read AFTER compound — always use fresh value
    let current_balance = balance::value(&vault.balance);
    let user_share = (amount * 10000) / current_balance;
    coin::from_balance(balance::split(&mut vault.balance, amount), ctx)
}
```

**Check:**
1. Does any function cache `balance::value()` early and use it after balance-modifying operations?
2. On Sui: can another PTB step modify a shared object's balance between read and use?
3. Prefer using return values of balance-modifying operations over pre-cached reads
4. Cross-ref: common-move.md 6.4

---

## Staking Verification Checklist

- [ ] First depositor attack mitigated — minimum dead shares burned or virtual reserves (DEFI-11)
- [ ] Reward accounting uses dedicated reward balance, not pool's total balance (DEFI-12)
- [ ] Reward accumulator uses u128 with PRECISION >= 1e12, multiplies before dividing (DEFI-13)
- [ ] Minimum stake duration enforced via on-chain timestamp (DEFI-14)
- [ ] Every function modifying reward rate or total staked calls `update_reward_index()` first (DEFI-15)
- [ ] No stale cached balance values used after balance-modifying operations (DEFI-16)
