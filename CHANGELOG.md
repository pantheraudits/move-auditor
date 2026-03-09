# Changelog

All notable changes to `move-auditor` are documented here.

Versioning follows [Semantic Versioning](https://semver.org/):
- **MAJOR** — breaking changes to skill interface or report format
- **MINOR** — new checks, new reference files, expanded coverage
- **PATCH** — fixes to existing checks, wording improvements, bug corrections

Each release is tagged as `move-auditor@X.Y.Z`.

---

## [2.3.0] — 2026-03-10

### False Positive Reduction — Benchmarking-driven verification improvements

Based on live benchmarking results that identified systematic false positive patterns,
this release strengthens the verification and triage phase with concrete kill mechanisms.

**SKILL.md — Phase 5 verification overhaul:**
- Enhanced Dimension 5 (Precondition Feasibility) with **Invariant Reachability Check**:
  trace every precondition back to constructors/setters to verify the required state is
  actually achievable on-chain
- Added **Dimension 8 — Counterfactual Fix Test**: apply the recommended fix mentally and
  verify it actually changes observable behavior. "Same outcome, different error code" is
  not a vulnerability
- Added **Mandatory Kill Questions** (Step 4): 5 concrete questions every VALID finding must
  answer — precondition construction, fix impact, established pattern check, victim/dollar
  quantification
- Added **Root-Cause Deduplication** (Step 5): group findings by the single line of code that
  would need to change, not by downstream effect
- Added **Dead Code / Unreachable Branch Detection** to Phase 3: verify code branches are
  reachable before recording findings; TODO comments are aspirational, not current bugs

**New file — `defi/defi-lending-design-patterns.md`:**
- DESIGN-L1: Spot prices for liquidation seize, EMA for eligibility (Compound/Aave standard)
- DESIGN-L2: Flash loan not updating accounting fields (hot potato guarantees correctness)
- DESIGN-L3: Blocking borrows when cash < reserve (protective, not DoS)
- DESIGN-L4: Asymmetric EMA/spot divergence formulas (intentional risk asymmetry)

**`defi/defi-liquidation.md` — Liquidation Economics Validation:**
- New section requiring economic viability analysis before reporting liquidation findings
- If the recommended fix makes liquidation unprofitable → the fix causes bad debt → worse
  than the "bug"

---

## [2.2.0] — 2026-03-09

### Expanded Pattern Coverage — 11 new patterns from community research

Integrated high-value patterns from [forefy/MOVE-CHECKS.md](https://github.com/forefy/.context/blob/main/skills/smart-contract-audit/MOVE-CHECKS.md),
deduplicated against existing checks, and placed in the correct chain-specific files.

**common-move.md** — 4 new chain-agnostic patterns:
- 7.4 Incomplete Pause Coverage — pause flag not checked on all public functions
- 7.5 Unpinned Dependencies in Move.toml — supply chain risk from unversioned git deps
- 9.4 Self-Transfer Snapshot Manipulation — self-transfer games fee/reward snapshots
- 9.5 Round-Trip Profitability — `withdraw(deposit(X)) <= X` invariant test

**sui-patterns.md** — 5 new Sui-specific patterns (SUI-23 to SUI-27):
- SUI-23: Shared Object Version Check (upgrade safety)
- SUI-24: Publisher Object Not Secured (Display/royalty spoofing)
- SUI-25: Dynamic Field Cleanup Before Object Deletion (orphaned fund loss)
- SUI-26: Kiosk Transfer Policy Bypass (royalty evasion)
- SUI-27: UpgradeCap Lifecycle Mismanagement (premature immutability / overly permissive policy)

**aptos-patterns.md** — 2 new Aptos-specific patterns (APT-22 to APT-23):
- APT-22: Struct Layout Change on Upgrade (binary deserialization failure)
- APT-23: Resource Account Signer Scope Creep (cross-module resource manipulation)

All verification checklists updated with corresponding new items.

---

## [2.1.0] — 2026-03-09

### Move-Expert Verify & Triage Phase

Added **Phase 5 — Verify & Triage** between vulnerability scanning and report output.
Every candidate finding must now survive a Move-expert validation pass before inclusion.

- **Dual Narrative Test:** Each finding requires a concrete Legitimate User Story vs
  Attacker Story with specific Move function calls, object/resource interactions, and
  quantified outcomes — vague findings are rejected
- **Move-Expert Disproof (7 Dimensions):** Challenges each finding against Move's type
  system & linearity, call path completeness, object/resource model (Sui ownership vs
  Aptos acquires), execution model reality (no delegatecall/callbacks), precondition
  feasibility (consensus ordering, gas costs), economic rationality, and existing protections
- **Finding Labels:** VALID, QUESTIONABLE, DISMISSED, OVERCLASSIFIED — only VALID and
  QUESTIONABLE findings reach the final report
- **Report format updated:** Added Triage Summary, Confidence field, Verification
  reasoning per finding, DISMISSED findings documented in Verified Clean Checks
- Previous Phase 5 (Report) renumbered to Phase 6
- Version bumped to 2.1.0

---

## [2.0.0] — 2026-03-09

### DeFi Deep-Dive — 69 new vulnerability patterns (DEFI-11 to DEFI-79)

Added 8 DeFi subcategory reference files under `defi/`, adapted from best-in-class
Solidity audit patterns and fully rewritten for Move (Sui & Aptos). Each pattern
includes vulnerable code, safe code, and auditor check instructions.

**defi/defi-staking.md** — 6 patterns (DEFI-11 to DEFI-16):
- First depositor share theft, reward dilution via direct transfer, precision loss
  in reward accumulators, flash deposit/withdraw griefing, stale reward index,
  balance caching mismatch

**defi/defi-oracle.md** — 8 patterns (DEFI-17 to DEFI-24):
- Stale price data (Pyth/Switchboard), same staleness threshold, decimal/exponent
  mismatch, wrong feed ID, depeg events, min/max price bounds, price direction
  confusion, missing circuit breakers

**defi/defi-lending.md** — 10 patterns (DEFI-25 to DEFI-34):
- Premature liquidation, collateral manipulation, loan closure without repayment,
  asymmetric pause, token denylist blocking repayment, no grace period, incorrect
  liquidation share, dust positions, forced debt, refinancing manipulation

**defi/defi-math-precision.md** — 8 patterns (DEFI-35 to DEFI-42):
- Division before multiplication, rounding to zero, decimal mismatch between tokens,
  unsafe u128→u64 downcasting, wrong rounding direction, inverted oracle pairs,
  time unit confusion (Sui ms vs Aptos seconds), exponentiation precision loss

**defi/defi-slippage.md** — 7 patterns (DEFI-43 to DEFI-49):
- Zero/missing min_amount_out, no deadline, hardcoded slippage, on-chain
  self-referential slippage, LP operation slippage, token vs USD confusion,
  PTB composability sandwich (Sui-specific)

**defi/defi-liquidation.md** — 17 patterns (DEFI-50 to DEFI-66):
- Incentive & mechanism (no incentive, small positions, collateral withdrawal,
  bad debt, partial bypass), calculation errors (decimals, fees, yield, swap fees,
  oracle sandwich), DoS vectors (unbounded loops, front-running, pending withdrawal,
  token freeze), fairness (grace period, post-liquidation health, no slippage)

**defi/defi-auction-clm.md** — 7 patterns (DEFI-67 to DEFI-73):
- Self-bidding timer reset, insufficient auction length, off-by-one seizure,
  missing TWAP on rebalance, TWAP parameter manipulation, stuck tokens from
  tick math rounding, retrospective fee application

**defi/defi-signatures.md** — 6 patterns (DEFI-74 to DEFI-79):
- Nonce replay, cross-chain replay (Sui↔Aptos), missing parameters in signed
  message, no expiration, unchecked verification return value, secp256k1
  signature malleability

### Skill infrastructure updates

- **SKILL.md**: Expanded reference table with 8 conditional-load DeFi files, updated
  Phase 1 (subcategory detection) and Phase 4 (subcategory loading), bumped to v2.0.0
- **defi-vectors.md**: Added DeFi Subcategory Detection Table, expanded verification
  checklist from 10 to 20 items with cross-references to new patterns
- **CLAUDE.md**: Updated contribution rules for `defi/` subdirectory
- **CONTRIBUTING.md**: Added DeFi subcategory file guide and next-ID tracking

---

## [1.0.0] — 2025-03-05

### Initial release

**SKILL.md**
- Auto-activation on `.move` files (Sui and Aptos detection)
- 5-phase audit workflow: Assessment → Multi-Perspective → Scan → DeFi → Report
- Structured report format with severity table, PoC scenarios, and fix recommendations
- Severity framework: Critical / High / Medium / Low / Info with Likelihood × Impact criteria

**common-move.md**
- Access control checks (SIG-01 to SIG-04): missing capability gates, copy-ability on caps, hardcoded addresses, two-step transfer
- Arithmetic checks: overflow DoS, division-before-multiplication, div-by-zero, cast truncation
- Resource safety: leaks, unauthorized extraction, double-spend via phantom resources
- Logic invariants: missing assertions, comparison operator bugs, state machine violations, timestamp manipulation
- Input validation: zero-value, address, vector bounds
- Cross-module safety: reentrancy, unvalidated returns, upgradeable dependencies
- Upgradeability: single-key authority, reinitialization, missing pause

**sui-patterns.md** — 10 checks (SUI-01 to SUI-10):
- Object ownership confusion
- Shared object reentrancy / PTB state inconsistency
- Witness pattern abuse (OTW copy-ability)
- Transfer to wrong owner
- Wrapping/unwrapping attacks
- Dynamic field injection
- Clock/epoch oracle manipulation
- Capability object theft/forgery
- Hot potato misuse
- Event spoofing

**aptos-patterns.md** — 11 checks (APT-01 to APT-11):
- Missing/incorrect `acquires` annotations
- Resource account privilege escalation
- Coin type confusion / generic type whitelist bypass
- Signer capability abuse
- Table/iterable table safety
- Timestamp oracle manipulation
- Event handle exhaustion / missing events
- Module upgrade safety
- FungibleAsset vs Coin framework mixing
- Unbounded vector / smart_vector growth
- `#[view]` function side effects

**defi-vectors.md** — 10 DeFi checks (DEFI-01 to DEFI-10):
- Oracle manipulation (spot price, TWAP, staleness)
- Flash loan attack surface
- Liquidity pool manipulation (first depositor, rounding, precision)
- Loan/borrow invariants
- Reward/yield calculation errors
- Liquidation mechanism abuse
- Slippage and front-running
- Interest rate model safety
- Governance/timelock bypass
- Bridge/cross-chain patterns

**sample-finding.md**
- Full example audit output with Critical and High findings, PoC scenarios, and fixes
