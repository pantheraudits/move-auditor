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

## DEFI-88 — Uninitialized Account Index = Full Historical Reward Credit

**Description:** Per-user position structs (`stake_account`, `spool_account`,
`UserPosition`, `Stake`) typically store a checkpoint field — `last_index`,
`reward_per_share_paid`, `last_reward_per_share`, `last_cumulative` — used to compute
rewards as `points = stake × (current_index − last_index)`. If the constructor that
creates a fresh account does **not** sync this checkpoint to the pool's *current*
index and instead leaves it at `0` (Move's struct-field default for numerics), the
first call to the reward-update path computes `current_index − 0 = full historical
accumulator`. The user is credited with every reward distributed since the pool
opened, even though they were not staked for any of it.

The reward accumulator is monotonically increasing and grows for the entire life of
the pool, so the longer the pool has run, the larger the impact. A pool whose
`current_index` has grown to ~10⁹ over 20 months will credit a freshly-created
account with **billions of times** its fair share.

**Why this often goes undetected for years:** the active SDK / front-end almost
always calls a setter (`set_last_index`, `sync_index`, `update_account`) immediately
after creating the account, masking the bug. The vulnerability only surfaces when
someone bypasses the SDK and calls the constructor + reward-claim path directly —
which is exactly the threat model on Sui because all historical package versions
remain executable forever (see SUI-23, Scallop incident).

**Pattern:**
```move
// VULNERABLE — last_index defaults to 0; first reward computation
// credits the account with the full historical accumulator
public struct SpoolAccount has key, store {
    id: UID,
    spool_id: ID,
    stake_amount: u64,
    last_index: u128,   // defaults to 0
    points: u128,
}

public fun new_account(spool: &Spool, ctx: &mut TxContext): SpoolAccount {
    SpoolAccount {
        id: object::new(ctx),
        spool_id: object::id(spool),
        stake_amount: 0,
        last_index: 0,        // <— BUG: should be spool.current_index
        points: 0,
    }
}

public fun stake(spool: &mut Spool, account: &mut SpoolAccount, coin: Coin<X>) {
    update_points(spool, account);  // reads (current_index − 0) = catastrophic
    account.stake_amount = account.stake_amount + coin::value(&coin);
    // ...
}

fun update_points(spool: &Spool, account: &mut SpoolAccount) {
    let delta_index = spool.index - account.last_index;
    let delta_points = (account.stake_amount as u128) * delta_index;
    account.points = account.points + delta_points;
    account.last_index = spool.index;
}

// SAFE — checkpoint is synced to the pool's current index at creation
public fun new_account(spool: &Spool, ctx: &mut TxContext): SpoolAccount {
    SpoolAccount {
        id: object::new(ctx),
        spool_id: object::id(spool),
        stake_amount: 0,
        last_index: spool.index,  // <— sync at construction
        points: 0,
    }
}
```

**Detection ritual:**
1. List every per-user position type that has a checkpoint field. Grep for field
   names matching:
   ```
   last_index | last_cumulative | last_reward_per_share | reward_per_share_paid
   | last_acc | last_update_index | last_checkpoint | reward_debt
   ```
   `reward_debt` is the MasterChef convention — it MUST be initialized to
   `stake × current_acc / PRECISION` at deposit time, not 0.
2. For each such type `P`, find every function that constructs it
   (`new_*`, `open_*`, `create_*`, `init_*`, or any function returning `P`). Read
   the field initializer. If the field is set to `0`, a literal, or `default()` —
   and the corresponding pool field is non-zero — that is the bug.
3. Trace every reward-update function (anything that computes
   `current_index - account.last_index`, `pool.acc - account.reward_debt`,
   etc.). If it can be reached by an account whose checkpoint has never been
   synced, the unsynced delta is creditable as rewards.
4. Map the call graph from every constructor to every reward-update function. If a
   path exists where the account reaches `update_points` / `harvest` / `claim`
   without first being synced to the pool's current index, flag as **Critical**.
5. Cross-check **all historical package versions**, not just the active one. On
   Sui, every old package is callable directly (SUI-23). A constructor that was
   buggy in V1/V2 and fixed in V3 still drains funds if the old package's
   constructor is callable on the live shared pool object. The combined
   SUI-23 + DEFI-88 finding is the exact Scallop class.
6. Sanity-check the math: at attack time, what does
   `stake × (current_index − 0) / PRECISION` evaluate to relative to the rewards
   pool size? If the result ≥ rewards pool balance, the protocol is drainable.

**Severity guidance:**
- Constructor leaves checkpoint at 0 AND a reward-claim path is reachable on the
  same package version → **Critical** (full drain, no special preconditions).
- Constructor leaves checkpoint at 0 but only the *deprecated* old package version
  has the bug AND that old package is callable (no SUI-23 gate) → **Critical**
  (this is the Scallop scenario).
- Constructor leaves checkpoint at 0 but every reward path performs a defensive
  sync before the first read → **Medium** (latent bug, defense-in-depth concern).

**Cross-reference:**
- SUI-23 — without a version gate, this bug stays exploitable on every old
  package version even after a fix is shipped.
- DEFI-13 — precision loss can mask or amplify the impact.
- DEFI-15 — admin functions skipping `update_reward_index()` create a related but
  distinct staleness class.
- semantic-gap-checks.md — the broader pattern of "state field whose write is
  conditional or skipped on creation".

*Ref: Scallop incident, April 2026 — 150K SUI drained via 17-month-old V2 package
where `spool_account.last_index` was never synced at creation. tx
`6WNDjCX3W852hipq6yrHhpUaSFHSPWfTxuLKaQkgNfVL`.*

---

## Staking Verification Checklist

- [ ] First depositor attack mitigated — minimum dead shares burned or virtual reserves (DEFI-11)
- [ ] Reward accounting uses dedicated reward balance, not pool's total balance (DEFI-12)
- [ ] Reward accumulator uses u128 with PRECISION >= 1e12, multiplies before dividing (DEFI-13)
- [ ] Minimum stake duration enforced via on-chain timestamp (DEFI-14)
- [ ] Every function modifying reward rate or total staked calls `update_reward_index()` first (DEFI-15)
- [ ] No stale cached balance values used after balance-modifying operations (DEFI-16)
- [ ] Per-user position constructors sync `last_index` / `reward_debt` / equivalent checkpoint to the pool's **current** accumulator — never leave at 0; check **every historical package version**, not just the active one (DEFI-88, Scallop class)
