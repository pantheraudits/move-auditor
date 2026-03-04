# Example Audit Output

This file shows what a high-quality finding looks like from the move-auditor skill.
Use this as a reference for output format and detail level.

---

## Audit Report — ExampleLending Protocol
**Chain:** Sui
**Date:** 2025-01-15
**Severity Summary:** 1 Critical, 2 High, 1 Medium, 2 Low, 1 Info

---

### [CRITICAL-001] Unchecked Coin Type Allows Worthless Token as Collateral

| Field      | Value |
|------------|-------|
| Severity   | Critical |
| Location   | `lending.move`, line 87, function `deposit_collateral` |
| Category   | Input Validation / Access Control |

**Description:**
The `deposit_collateral` function accepts any `CoinType` as collateral without validating
that it is an approved asset. An attacker can create a custom worthless token, deposit it
as collateral, and borrow real assets against it.

**Attack Scenario (PoC):**
1. Attacker deploys `module attacker::junk_token` and mints 1,000,000 JUNK tokens
2. Attacker calls `deposit_collateral<attacker::junk_token::JUNK>(1_000_000)`
3. Protocol accepts JUNK as collateral (no whitelist check)
4. Attacker calls `borrow<SUI>(900_000_SUI_MIST)` — protocol allows borrow up to 90% LTV
5. Attacker walks away with real SUI, leaving worthless JUNK as collateral
6. Protocol is insolvent

**Recommended Fix:**
Add a whitelist of approved collateral types enforced on-chain:
```move
// Add to protocol's shared config object
struct Config has key, store {
    id: UID,
    approved_collateral: vector<TypeName>,
    // ...
}

// Add whitelist check to deposit_collateral
public entry fun deposit_collateral<CoinType>(
    config: &Config,
    pool: &mut LendingPool,
    coin: Coin<CoinType>,
    ctx: &mut TxContext
) {
    let type_name = type_name::get<CoinType>();
    assert!(
        vector::contains(&config.approved_collateral, &type_name),
        E_COLLATERAL_NOT_APPROVED
    );
    // ... rest of function
}
```

---

### [HIGH-001] Flash Loan Enables Oracle Manipulation for Collateral Valuation

| Field      | Value |
|------------|-------|
| Severity   | High |
| Location   | `oracle.move`, line 34, function `get_price` |
| Category   | Oracle Manipulation |

**Description:**
`get_price()` returns the current spot ratio of the liquidity pool reserves:
`price = pool.reserve_b / pool.reserve_a`. This is manipulable in a single transaction
using a flash loan to temporarily skew the pool ratio, borrow against inflated collateral,
then repay the flash loan — keeping the profit.

**Attack Scenario (PoC):**
1. Attacker takes flash loan of 10,000 SUI
2. Swaps all 10,000 SUI into USDC in target pool → pool ratio now shows USDC worth 10x normal
3. Calls `borrow` using USDC as collateral — oracle reads inflated price
4. Borrows 5,000 SUI against now-"valuable" USDC
5. Swaps USDC back to SUI (restoring pool ratio)
6. Repays flash loan of 10,000 SUI
7. Net profit: ~5,000 SUI minus fees

**Recommended Fix:**
Replace spot price with a TWAP (Time-Weighted Average Price) using at least a 30-minute window:
```move
// Store price observations
struct PriceObservation has store {
    price: u128,
    timestamp: u64,
}

// Compute TWAP from stored observations
public fun get_twap_price(pool: &Pool): u128 {
    // ... compute weighted average over observations
}
```

---

### Verified Clean Checks

- ✅ Access control: All entry functions require valid signer or capability
- ✅ Arithmetic: No overflow/underflow DoS vectors found
- ✅ Capability abilities: All capability structs have `drop` only
- ✅ Object transfer: Recipient validated as tx sender in all transfer functions
- ✅ Initialization: `init()` function is one-time-only

---

### Auditor Notes

- Test coverage is low (~40%). Core invariants are not tested. Recommend adding invariant tests before deployment.
- The protocol has a single-key upgrade authority with no timelock. Post-deployment, consider migrating to a multisig.
- All findings above must be manually verified and PoC-tested before inclusion in a final report. AI analysis may miss context.
