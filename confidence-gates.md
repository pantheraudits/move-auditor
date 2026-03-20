# Confidence Gates

Load this file during **Phase 7 — Verify & Triage**. It defines a multi-signal
confidence model that prevents low-evidence findings from receiving high severity.

---

## Section 1: Confidence Levels

Every finding must be assigned one of these confidence levels:

| Level | Definition | Required signals | Max severity allowed |
|-------|-----------|-----------------|---------------------|
| `confirmed` | Two or more independent signals corroborate the finding | 2+ from Section 2 | Critical / High / Medium / Low |
| `likely` | One strong signal supports the finding | 1 strong signal (strength ≥ 3) | High (if signal is strong) / Medium / Low |
| `needs_review` | Pattern match only — no concrete corroboration | 0-1 weak signals | **Medium max** — cannot be High or Critical |

### Rules

- A finding at `needs_review` confidence can NEVER be rated High or Critical.
- `confirmed` requires signals from at least two different categories (e.g., code
  pattern + math proof, not two code patterns).
- If you cannot achieve `likely` or better, the finding should be `QUESTIONABLE`
  in the triage label AND capped at Medium severity.

---

## Section 2: Signal Types for Move Audits

Signals are ordered from weakest to strongest. Each has a numeric strength for gating.

| # | Signal Type | Strength | Description | Example |
|---|------------|----------|-------------|---------|
| 1 | Code pattern match | 1 (weakest) | "This looks like vulnerable pattern X" | Function takes shared object without auth check |
| 2 | Missing check confirmed in source | 2 | Verified that a specific validation is absent by reading the code | No `assert!(sender == admin)` in `set_fee()` — confirmed by reading lines 1-50 |
| 3 | Exploitable call path traced | 3 | Full path from entry point to vulnerable code, all intermediate checks verified | `entry fun liquidate()` → `internal_seize()` → no cash check at line 42 |
| 4 | Mathematical proof | 4 | Algebraic demonstration with concrete values showing overflow/precision loss | `reward_per_share * user_shares` overflows u64 when shares > 10^12 and rate > 10^7 |
| 5 | Concrete PoC pseudocode | 4 | Step-by-step PTB/tx sequence with specific function calls and arguments | PTB: `1. borrow_flash() 2. manipulate_price() 3. borrow() 4. repay_flash()` |
| 6 | Known-vulnerable pattern from real audit | 3 | Pattern matches a documented vulnerability from a published audit report | Matches CertiK finding in Protocol X: same accumulator-before-checkpoint pattern |
| 7 | Test log abort matching claimed bug | 4 | Project's own tests show abort at the exact location/condition claimed | `sui move test` shows `arithmetic_error` at `rewards.move:87` — matches overflow claim |
| 8 | On-chain state confirming precondition | 5 (strongest) | Production data shows the prerequisite state exists or is reachable | Mainnet pool has $50M TVL with reward_rate that triggers overflow after 10 hours |

### Signal Combination Examples

| Signals present | Confidence | Rationale |
|----------------|-----------|-----------|
| #1 only (pattern match) | `needs_review` | No corroboration |
| #2 + #4 (missing check + math proof) | `confirmed` | Two independent signals from different categories |
| #3 only (call path traced) | `likely` | One strong signal (strength 3) |
| #5 + #7 (PoC + test abort) | `confirmed` | Two strong signals |
| #1 + #2 (pattern + missing check) | `likely` | One strong signal (#2), one weak (#1) |

---

## Section 3: Hard Evidence Requirements

For each finding type, the following evidence is NEVER optional. A finding without
its required evidence is automatically `needs_review` regardless of other signals.

### Access Control Bypass
- [ ] Exact missing check identified (file:line where check should be)
- [ ] Who can call the function (entry point classification)
- [ ] What object, signer, or capability is needed vs what is checked
- [ ] Proof that attacker can obtain/access the required inputs

### Arithmetic Overflow / Precision Loss
- [ ] Concrete input values that trigger the overflow
- [ ] Proof those values are reachable in production (token decimals, supply ranges)
- [ ] Impact calculation: what happens after the overflow (abort = DoS or corruption?)
- [ ] For fixed-point: overflow bound derived from helper source (not assumed)

### Oracle Manipulation
- [ ] Price impact calculation: how much capital needed to move price by X%
- [ ] Profit vs cost analysis: flash loan fee + gas + slippage vs extracted value
- [ ] Time window: how long does the manipulated state persist?
- [ ] Alternative oracle check: does the protocol use TWAP, Pyth, or other resistant oracle?

### Flash Loan Attack
- [ ] Full PTB/tx sequence: loan → manipulate → profit → repay
- [ ] Flash loan source identified (which protocol/pool)
- [ ] Intermediate state during flash loan that enables the exploit
- [ ] Hot potato correctly handled (or not) in the sequence

### Reentrancy (Cross-Module State Mutation)
- [ ] Cross-module state mutation path: module A writes, module B reads stale
- [ ] Move has no callbacks — explain the specific mechanism (PTB composition, friend calls)
- [ ] State that becomes inconsistent between the two operations
- [ ] Why the inconsistency is exploitable (not just theoretical)

### Front-Running / MEV
- [ ] Proof attacker can observe the target transaction
  - Sui: **no public mempool** — requires validator collusion or specific conditions
  - Aptos: mempool exists — front-running is feasible
- [ ] Time window for front-running
- [ ] Economic incentive exceeds cost of attack

### Stale State / State Desync
- [ ] Writer path: which function updates the state (file:line)
- [ ] Consumer path: which function reads stale state (file:line)
- [ ] Persistence window: how long can stale state persist?
- [ ] Numeric trace: concrete values showing stale vs fresh state difference

### DoS via Abort
- [ ] Reachable caller: who triggers the abort (entry point)
- [ ] Input values that cause the abort
- [ ] Economic impact: what is blocked? (withdrawals, liquidations, all operations)
- [ ] Recovery path: can the protocol recover, or is it permanent?

---

## Section 4: Completeness Thresholds

Minimum analysis requirements to ensure thorough coverage.

### Per Entry Point

Before marking an entry point as "reviewed," ensure:
- [ ] At least 2 invariants identified and verified (or "none applicable" with reason)
- [ ] At least 3 assumptions documented (e.g., "caller is owner," "amount > 0," "oracle is fresh")
- [ ] All state-mutating paths traced to completion
- [ ] All abort conditions cataloged with reachability assessment

### Per Finding

Before including a finding in the report:
- [ ] Evidence audit table completed (from `verification-policy.md`)
- [ ] Confidence level assigned (`confirmed` / `likely` / `needs_review`)
- [ ] At least 1 concrete value trace (not just "could overflow")
- [ ] Self-hallucination check passed (5-point protocol — re-read source after concluding)
- [ ] Devil's advocate questions 1-11 answered (structured challenge protocol)

---

## Section 5: Confidence Gate Checklist

Run this 6-gate checklist on every finding before finalizing. ALL gates must pass
for the finding to proceed at its claimed severity.

### Gate 1: Process Gate
- [ ] Finding survived Phase 7 Step 1 (Dual Narrative Test)
- [ ] Finding survived Phase 7 Step 2 (8-Dimension Disproof)
- [ ] Finding survived Phase 7 Step 4 (Kill Questions 1-6)
- If any step was skipped → finding cannot be VALID

### Gate 2: Reachability Gate
- [ ] Attacker-accessible entry point identified
- [ ] Full call path traced from entry to vulnerable code
- [ ] All intermediate checks verified (none block the path)
- [ ] Precondition state achievable through valid protocol operations
- If reachability is uncertain → confidence capped at `needs_review`

### Gate 3: Real Impact Gate
- [ ] Specific victim identified (users, LPs, protocol treasury)
- [ ] Dollar-denominated impact estimated (or "non-financial: [description]")
- [ ] Impact survives economic rationality check (profit > cost for attacker)
- If impact is speculative → severity capped at Medium

### Gate 4: PoC Gate
- [ ] Concrete PoC pseudocode written (PTB or transaction script)
- [ ] PoC uses only functions available to the attacker (correct visibility)
- [ ] PoC accounts for gas costs and transaction fees
- If no PoC → confidence capped at `likely`, severity capped at Medium

### Gate 5: Math Bounds Gate
- [ ] All arithmetic claims backed by concrete values
- [ ] Overflow/precision bounds derived from type maximums AND realistic ranges
- [ ] Token decimals and supply ranges sourced from production data or reasonable estimates
- If math is hand-waved → finding cannot be `confirmed`

### Gate 6: Move Safety Gate
- [ ] Finding does not assume EVM capabilities (reentrancy, delegatecall, storage collision)
- [ ] Finding accounts for Move's type system protections (linearity, abilities, no dynamic dispatch)
- [ ] Finding accounts for chain-specific properties (Sui: owned objects, PTB model; Aptos: signer, acquires)
- If finding relies on non-Move assumptions → DISMISSED
