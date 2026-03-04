# Common Move Security Patterns

Chain-agnostic security checks that apply to all Move code, regardless of whether
it targets Sui or Aptos. Run these on every audit before loading chain-specific patterns.

---

## 1. Access Control

### 1.1 Missing Signer/Capability Validation
**Pattern:** `public entry fun` with no `&signer` parameter and no capability check.
**Risk:** Anyone can call the function.
**Check:** Every state-mutating entry function must either:
- Accept a `&signer` and validate it against a stored admin/owner address, OR
- Accept a capability object that is unforgeable (no `copy` ability)

```move
// VULNERABLE — no access control
public entry fun set_fee(new_fee: u64) {
    borrow_global_mut<Config>(@admin).fee = new_fee;
}

// SAFE — capability gating
public entry fun set_fee(cap: &AdminCap, new_fee: u64) {
    borrow_global_mut<Config>(@admin).fee = new_fee;
}
```

### 1.2 Overly Broad Capability Abilities
**Pattern:** Capability struct has `copy` or `store` ability.
**Risk:** Capabilities can be duplicated or stored arbitrarily, defeating the access model.
**Check:** Administrative capability structs should have zero or only `drop` ability.

```move
// VULNERABLE
struct AdminCap has copy, store, drop {}

// SAFE
struct AdminCap has drop {}
```

### 1.3 Hardcoded Address Checks
**Pattern:** `assert!(signer::address_of(account) == @0x1234, E_NOT_ADMIN)`
**Risk:** Admin address is immutable; if key is lost, the protocol is bricked. No upgrade path.
**Check:** Flag hardcoded address checks. Prefer capability-based patterns.

### 1.4 Two-Step Ownership Transfer Missing
**Pattern:** Ownership transferred in a single step without confirmation.
**Risk:** Typo in address permanently locks the protocol.
**Check:** Critical ownership transfers should use a pending → accept pattern.

---

## 2. Arithmetic & Overflow

### 2.1 Unchecked Integer Arithmetic
**Pattern:** Addition, subtraction, multiplication without overflow/underflow checks.
**Risk:** In Move, integer overflow **aborts** by default — but subtraction underflow on `u64` is a runtime abort that can be used as a DoS.
**Check:** Verify that arithmetic paths can't be forced into abort by a malicious caller.

```move
// POTENTIAL DOS — attacker supplies balance = 0
let result = balance - fee; // aborts if fee > balance
```

### 2.2 Division Before Multiplication (Precision Loss)
**Pattern:** `(a / b) * c` instead of `(a * c) / b`
**Risk:** Integer division truncation causes systematic precision loss, exploitable in DeFi.
**Check:** In any fee/interest/share calculation, verify multiplication happens before division.

### 2.3 Division by Zero
**Pattern:** Division where denominator can be zero.
**Risk:** Runtime abort (DoS).
**Check:** All divisions must assert denominator != 0.

### 2.4 Cast Truncation
**Pattern:** Casting from larger to smaller integer type (e.g., `u128` → `u64`).
**Risk:** Silent truncation of high bits.
**Check:** All narrowing casts should have bounds assertions.

---

## 3. Resource Safety

### 3.1 Resource Leak
**Pattern:** A resource is created but never moved to storage or dropped.
**Risk:** Move's type system prevents this at compile time — but check for structs without `drop` that might be accidentally destructured.
**Check:** All `key`-ability structs must end up in global storage. If a function creates a resource, trace where it goes.

### 3.2 Unauthorized Resource Extraction
**Pattern:** `move_from<T>(addr)` without verifying the caller owns that address.
**Risk:** Theft of stored resources.
**Check:** Every `move_from` must be preceded by an ownership/capability check.

```move
// VULNERABLE
public entry fun withdraw(account: &signer, target: address) {
    let coin = move_from<CoinStore>(target); // no ownership check!
    // ...
}
```

### 3.3 Borrow After Move
**Pattern:** Using a reference to a value after it has been moved.
**Risk:** Caught by the type system, but watch for patterns that try to work around it.

### 3.4 Double Spend via Phantom Resources
**Pattern:** Protocol tracks balances off-chain or in a separate table while actual assets flow differently.
**Risk:** Inconsistency between accounting and actual assets.
**Check:** For every credit to internal accounting, verify there is a corresponding on-chain asset transfer.

---

## 4. Logic & Invariant Violations

### 4.1 Missing Invariant Assertions
**Pattern:** Protocol has documented invariants (e.g., "total supply == sum of all balances") with no on-chain enforcement.
**Risk:** Invariants can drift due to edge cases, creating exploitable inconsistencies.
**Check:** Critical invariants should be checked with `assert!` at the end of state-mutating functions, especially during development/testing.

### 4.2 Incorrect Comparison Operators
**Pattern:** `>` vs `>=`, `<` vs `<=` in boundary checks.
**Risk:** Off-by-one exploits in withdrawal limits, stake amounts, etc.
**Check:** Every boundary condition — pay extra attention to fee calculations, minimum deposits, maximum withdrawals.

### 4.3 State Machine Violations
**Pattern:** State enum transitions without exhaustive checks.
**Risk:** Skipping states or transitioning to invalid states.
**Check:** Map all state machine transitions. Verify each is gated and exhaustive.

### 4.4 Timestamp/Epoch Manipulation
**Pattern:** Logic that depends on `Clock` (Sui) or `timestamp::now_seconds` (Aptos).
**Risk:** Validators have limited but real ability to influence block timestamps. Flash-loan window exploits.
**Check:** Avoid hardcoded time windows shorter than ~30 seconds. Flag any logic where timestamp manipulation gives economic benefit.

---

## 5. Input Validation

### 5.1 Missing Zero-Value Checks
**Pattern:** Functions that accept `amount: u64` without asserting `amount > 0`.
**Risk:** Zero-value operations that corrupt state, skip logic, or trigger division-by-zero downstream.

### 5.2 Missing Address Validation
**Pattern:** Functions that accept `address` parameters without validating they are non-zero or known.
**Risk:** Sending to zero address, interacting with uninitialized modules.

### 5.3 Length/Bounds Checks on Vectors
**Pattern:** Accessing `vector<T>` by index without bounds checking.
**Risk:** Runtime abort (DoS) if index is out of bounds.
**Check:** All vector index operations should be bounds-checked or use safe access patterns.

---

## 6. Cross-Module & External Call Safety

### 6.1 Reentrancy via Cross-Module Calls
**Pattern:** Calling an external module function while holding mutable borrows or mid-state-update.
**Risk:** Move doesn't have EVM-style reentrancy, but cross-module calls while in inconsistent state can still be exploited.
**Check:** Ensure state is in a consistent, valid state before any external call. Update state after, not before external calls (checks-effects-interactions pattern).

### 6.2 Unvalidated Return Values
**Pattern:** Return values from external module calls used without validation.
**Risk:** External module could return unexpected values.
**Check:** Validate all values returned from external calls before using them in critical logic.

### 6.3 Dependency on Upgradeable Modules
**Pattern:** Protocol depends on an external module that can be upgraded.
**Risk:** Upgrade changes behavior, breaking assumptions.
**Check:** Flag all external module dependencies. Note which are upgradeable.

---

## 7. Upgradeability & Admin Risks

### 7.1 Unconstrained Upgrade Authority
**Pattern:** Single key controls upgrades with no timelock or multisig.
**Risk:** Compromised key = full protocol takeover.
**Check:** Upgrade authority should be governed. Flag single-key upgrade authority as Medium/High depending on TVL.

### 7.2 Initialization Functions Callable Multiple Times
**Pattern:** `init` or `initialize` function that can be called by anyone after deployment.
**Risk:** Reinitialization overwrites config, disables the protocol, or escalates privileges.
**Check:** Initialization must be one-time-only, enforced on-chain.

```move
// VULNERABLE — anyone can reinitialize
public entry fun initialize(admin: &signer, config: Config) {
    move_to(admin, config);
}

// SAFE — aborts if already initialized
public entry fun initialize(admin: &signer, config: Config) {
    assert!(!exists<Config>(signer::address_of(admin)), E_ALREADY_INITIALIZED);
    move_to(admin, config);
}
```

### 7.3 Emergency Pause Missing
**Pattern:** No circuit breaker / pause mechanism.
**Risk:** In an active exploit, there's no way to halt the protocol.
**Check:** Note absence of pause mechanism. Not a vulnerability itself, but an operational risk worth flagging as Info.

---

## Verification Checklist

Run through each item and mark ✅ (clean) or ❌ (finding):

- [ ] All entry functions have access control
- [ ] No capability structs with `copy` ability
- [ ] All arithmetic checked for overflow/underflow DoS
- [ ] No division before multiplication in financial math
- [ ] All divisions guarded against zero denominator
- [ ] No narrowing casts without bounds assertions
- [ ] All `move_from` calls preceded by ownership check
- [ ] No timestamp dependencies exploitable in <30s window
- [ ] All user inputs validated (zero checks, bounds checks)
- [ ] State consistent before all external calls
- [ ] Initialization is one-time-only
- [ ] Upgrade authority is governed or noted

> **Deep-dive prompts and the Move Vulnerability Patterns prompt pack have been moved to
> `audit-prompts.md` in this directory.** Load that file for targeted per-module,
> per-function, and adversarial-scenario prompts derived from 1141 real findings
> across 200+ Move audit reports.
