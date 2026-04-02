# Changelog

All notable changes to `move-auditor` are documented here.

Versioning follows [Semantic Versioning](https://semver.org/):
- **MAJOR** — breaking changes to skill interface or report format
- **MINOR** — new checks, new reference files, expanded coverage
- **PATCH** — fixes to existing checks, wording improvements, bug corrections

Each release is tagged as `move-auditor@X.Y.Z`.

---

## [3.6.1] — 2026-04-03

### Audit methodology improvements — admin analysis, parallel subsystem checks, bit-shift safety

- **SKILL.md Phase 2**: Added Perspective 5 — Bidirectional Admin Checker. Every admin
  function now mandates analysis in both directions (admin→user harm AND user→admin grief)
- **SKILL.md Phase 7**: Added Step 6 — Post-Confirmation Parallel Subsystem Check. After
  confirming any Medium+ finding, grep all call sites and verify the same bug doesn't exist
  in parallel subsystems (deposit/borrow, token0/token1, pool A/pool B)
- **common-move.md 2.5**: Added Bit-Shift Wrapping (Silent Overflow). Move bit-shifts
  (`<<`/`>>`) silently wrap instead of aborting — unlike standard arithmetic. Off-by-one
  in custom overflow checks produces corrupted results, not aborts

---

## [3.6.0] — 2026-04-01

### Aptos Patterns Enhancement — input validation, object safety, testing

Expanded Aptos-specific coverage with new input validation checks, stronger object
safety guidance, and build/test tooling for Phase 1 detection.

**aptos-patterns.md — 1 new pattern + 2 enhanced checks:**
- APT-25: Input Validation Gaps — structured 6-category checklist for Aptos entry function
  parameter validation (zero amount, max limit, vector length, string length, zero address,
  enum-like range). Cross-references APT-13, APT-10, common-move 2.1
- APT-17 enhanced: Added ungated transfer control (`object::set_untransferable()`) and
  DeleteRef discipline checks — objects that shouldn't be freely transferable or deletable
  now have explicit verification items
- Aptos Verification Checklist: 3 new items for APT-25, ungated transfers, DeleteRef safety
- Aptos Build & Test Commands: Added `aptos move compile`, `aptos move test --coverage`,
  `aptos move coverage summary`, `aptos move coverage source` commands for Phase 1 build
  detection, with coverage threshold guidance

**SKILL.md:**
- Updated aptos-patterns.md reference range from APT-24 to APT-25

---

## [3.5.0] — 2026-03-27

### Expanded Sui Patterns & Logic Checks — 16 new vulnerability patterns

Broadens Sui-specific coverage with 13 new checks (SUI-30 to SUI-42) targeting
object model design flaws, shared object contention, composability anti-patterns,
and Sui framework misuse. Also adds 3 new chain-agnostic logic checks to
`common-move.md` for subtle security bugs that static analysis misses.

**common-move.md — 3 new chain-agnostic patterns:**
- 1.6: Authorization returns bool without assertion — callers can silently discard
  the result, bypassing access control entirely
- 4.5: Inverted security logic — checks that block the wrong party, use the wrong
  comparison direction, or assert the opposite of the intended condition
- 4.6: Wrong field update — functions that modify a different same-typed field than
  intended (compiler cannot catch field swaps between `u64` fields)
- 3 new verification checklist items for the above

**sui-patterns.md — 13 new Sui-specific patterns (SUI-30 to SUI-42):**
- SUI-30: VecMap/VecSet for unbounded collections — O(n) DoS when user-driven growth exceeds ~1K entries
- SUI-31: Shared object contention — excessive `&mut` on read-only paths forces consensus ordering
- SUI-32: Blind transfer without receive logic — objects transferred to object addresses with no extraction path
- SUI-33: `address` type where `ID` should be used — loses type safety for object references
- SUI-34: Internal transfer instead of return — breaks PTB composability
- SUI-35: Batch function instead of PTB loop — unnecessary complexity, vector mismatch risk
- SUI-36: Solidity-style auth (address→role maps) instead of Move capability objects
- SUI-37: Framework type name shadowing — user types named CoinMetadata, TreasuryCap, Publisher, etc.
- SUI-38: Metadata/Display frozen before required fields set — irreversible
- SUI-39: Multiple Publisher objects per package — split authority, governance complexity
- SUI-40: Unnecessary `public(package)` visibility — attack surface expansion
- SUI-41: NFT stores constant fields — per-collection data belongs in Display templates, not per-instance structs
- SUI-42: Migration function in non-upgraded v1 package — dead code
- 14 new verification checklist items for the above

**SKILL.md:**
- Updated sui-patterns.md reference range: SUI-01 to SUI-42 (was SUI-01 to SUI-28)
- Version bumped to 3.5.0

---

## [3.4.0] — 2026-03-21

### Anti-False-Positive Overhaul — TOB-inspired confidence gating and evidence chains

Benchmarking against CurrenSui revealed a ~25% false positive rate, mostly from
LLM rationalizations, pattern-matching without data flow analysis, and inflated
severity on non-exploitable findings. This release integrates anti-FP techniques
adapted from Trail of Bits' skills (rationalizations tables, confidence gating,
evidence templates, FP catalogs, devil's advocate reviews) into the Move auditor.

**New files:**

- **`move-fp-catalog.md`** (Always loaded) — 10-row rationalizations table of
  Move-specific LLM shortcuts to reject, 29+ false positive patterns across 5
  categories (Sui Object Model, Move Type System, Abort Semantics, PTB Composition,
  DeFi Design Patterns), and a 5-point self-hallucination check protocol
- **`evidence-chains.md`** (Phase 7) — Structured evidence templates: data flow
  with Move trust levels, mathematical bounds proofs, attacker control analysis,
  PoC pseudocode (Sui PTB / Aptos tx format), negative PoC for dismissals, and
  13-question devil's advocate protocol
- **`confidence-gates.md`** (Phase 7) — Multi-signal confidence gating: 3 levels
  (`confirmed`/`likely`/`needs_review`), 8 ranked signal types, hard evidence
  requirements per finding type, completeness thresholds, 6-gate checklist

**SKILL.md changes (net reduction: 538 → 497 lines):**
- Removed Known FP Patterns section (migrated to `move-fp-catalog.md` Section 2E)
- Removed Quick Maturity Assessment (low value, covered by reference files)
- Added "When NOT to Use" section
- Added 3 new files to Reference Files table
- Phase 7 now loads `evidence-chains.md` and `confidence-gates.md`
- Kill Question 6: mandatory self-hallucination check
- Step 3 labels now include confidence levels (`confirmed`/`likely`/`needs_review`)
- Condensed verbose prose throughout

**Modified files:**
- `verification-policy.md` — added Hard Evidence Requirements cross-reference and
  Confidence Gating section with severity caps
- `checklist-router.md` — added `move-fp-catalog.md` to Always Load, added
  Verification Phase Loading section for evidence-chains and confidence-gates
- `sample-finding.md` — added second example finding demonstrating evidence chain
  table, signal strengths, confidence level, recoverability assessment, and gate verification

---

## [3.3.0] — 2026-03-19

### Workflow and verification improvements

Adds three new reference files that improve coverage selection, state-consistency
review, and verification rigor for subtle High/Critical Move bugs:

- **`checklist-router.md`** — improves coverage planning from detected protocol signals
- **`semantic-gap-checks.md`** — adds a dedicated stale-state and state-desync review pass
- **`verification-policy.md`** — strengthens exploitability validation and severity discipline

**SKILL.md:**
- Added the 3 new files to Reference Files and made `verification-policy.md` +
  `checklist-router.md` mandatory on every audit
- **Phase 1:** now requires a router-driven coverage plan instead of purely
  heuristic file loading
- **Phase 5:** new Semantic Gap & Stale-State Scan before cross-module interaction review
- **Verify & Triage:** now applies stronger evidence requirements plus
  reachability/math feasibility gates
- Report triage now uses the existing finding labels with stronger evidence requirements

**README.md:**
- Documented the new router-driven coverage step, semantic-gap pass, and
  stronger verification workflow
- Added the 3 new files to the published skill structure

This release is focused on reducing false refutations and improving detection of
state-desync bugs such as stale checkpoints, skipped accumulator writes,
cross-module cleanup gaps, and dual-source metric inconsistencies.

## [3.2.0] — 2026-03-17

### Build & Test Log Analysis — Runtime-informed vulnerability detection

Adds a conditional build-and-test phase to the audit workflow. When the target project
compiles, the auditor runs the test suite, captures output, and systematically analyzes
logs for arithmetic aborts, assertion failures, expected-failure annotations, and edge-case
panics that may indicate latent High/Critical bugs invisible to static-only pattern matching.

**SKILL.md:**
- **Phase 1:** Added Build Detection gate — checks `Move.toml` + runs `sui move build` or
  `aptos move compile`. Sets `BUILD_AVAILABLE` flag. If build fails, logs errors and skips
  test analysis. If build succeeds, runs Test Log Analysis (common-move.md Section 13)

**common-move.md:**
- **Section 13 — Build & Test Log Analysis** (full procedure):
  - 13.1: Build Verification — compile check with error categorization
  - 13.2: Test Execution & Log Capture — run test suite with output capture
  - 13.3: Log Analysis — 5 signal categories: arithmetic aborts, assertion failures,
    expected-failure annotations, test failures/skipped tests, gas/execution limits
  - 13.4: Triage & Escalation — priority table with escalation rules; arithmetic aborts
    in financial modules auto-escalate to Recoverability Matrix analysis
  - 13.5: Reporting — structured TEST-NNN format with cross-referencing to main findings
- **1 new verification checklist item** for Section 13

**README.md:**
- Added "Best results" section explaining the skill works best on buildable projects
- Documented static-only fallback mode for non-buildable code

---

## [3.1.0] — 2026-03-17

### Arithmetic/Accounting DoS — Catch hidden fixed-point overflow and accumulator deadlock

Based on a missed High-severity finding in a Sui lending protocol where a multiply-before-divide
overflow inside a fixed-point helper permanently froze all lending operations. The overflow
occurred in `float::mul` before the normalizing division could execute, and the abort happened
before `last_update_time_ms` was checkpointed — creating an irrecoverable deadlock.

**common-move.md:**
- **2.6 Fixed-Point Helper Library Overflow:** Mandatory check to open fixed-point helper modules
  (`float`, `decimal`, `wad_ray`) and derive internal overflow bounds for `mul`/`div`/`from`.
  Targets hidden overflow where calling code looks safe (`A.mul(B).div(C)`) but the helper
  aborts before `div(C)` executes
- **12.1 Abort-Before-Checkpoint Deadlock:** Checks that state checkpoints (`last_update_time`,
  `cumulative_index`) are written before or atomically with potentially-aborting arithmetic.
  Includes concrete example with reward manager pattern
- **12.2 Admin-Origin Latent User DoS:** Explicit guidance that admin-configured parameters
  are reportable as High/Critical when users/liquidators are later bricked
- **Recoverability Matrix:** Mandatory 7-question matrix for every DoS candidate — traces
  cancel/claim/close/emergency paths to determine if deadlock is temporary, conditional,
  or permanent
- **4 new verification checklist items** for sections 2.6, 12.1, 12.2

**defi/defi-math-precision.md:**
- **DEFI-85:** Multiply-Before-Divide Overflow in Fixed-Point Helpers — full analysis
  methodology with 3-step process (derive helper bounds → compute overflow threshold →
  build threshold table with production token decimals). Includes worked example with
  USDC/SUI reward programs showing overflow at 10.25 hours / 5.12 hours of inactivity
- **DEFI-86:** Accumulator Checkpoint Liveness — detects abort-before-state-advance
  patterns in reward/interest accumulators. Includes entry point tracing checklist
- **3 new verification checklist items** for DEFI-85, DEFI-86

**SKILL.md:**
- **Phase 3:** Added mandatory fixed-point helper inspection step — auditor must open
  helper source and derive overflow bounds, not trust calling code at face value
- **Phase 5 pair 9:** `reward_manager_update ↔ all lending operations` — checks whether
  accumulator abort-before-checkpoint traps all user and admin paths
- **Severity Reference:** Added admin-origin latent user DoS guidance — severity is based
  on who is blocked (users/liquidators), not who created the configuration

### Impact
This release ensures the auditor will:
1. Always open and inspect fixed-point math helper internals (not just calling code)
2. Derive concrete overflow bounds using production token decimals and time units
3. Check checkpoint ordering in every accumulator update function
4. Trace all entry points through stuck accumulators (including admin cancel/close)
5. Never dismiss a finding as "admin-only" when users are the actual victims
6. Complete a Recoverability Matrix before assigning DoS severity

---

## [3.0.0] — 2026-03-14

### Added
- **SUI-28:** PTB Repeated Call Limit Bypass — close factor, rate limits, cooldowns bypassed via multi-call PTBs
- **DEFI-83:** Close Factor Cumulative Enforcement — per-transaction vs per-call limit tracking
- **DEFI-84:** Admin Config Update Resets Embedded Runtime State — limiters, accumulators destroyed by config writes
- **DESIGN-L1 caveat:** Missing EMA-spot divergence tolerance in liquidation path
- **DEFI-54 enhancement:** Sui PTB amplification note for partial liquidation bypass
- **Phase 2 Perspective 4:** Symmetry Checker (deposit/withdraw, borrow/repay, mint/burn, trigger/seize)
- **Phase 5 pairs 5-8:** New mandatory cross-module interaction checks
- **Known False Positive Patterns:** 5 patterns that appear vulnerable but are commonly intentional
- **Quick Maturity Assessment:** Adapted from Trail of Bits Code Maturity Framework
- **APT-24:** Unchecked Signer Parameter — `&signer` accepted without `signer::address_of` authorization check
- **Phase 1 Entry Point Classification:** Sui vs Aptos visibility table showing that ALL `public fun` are PTB-callable on Sui
- **Phase 1 Access Control Classification:** Heuristic for classifying entry points by access tier (Public/Owner/Role/Review Required)
- Trail of Bits methodology integration: asymmetry detection, secure-by-default checks, entry-point-analyzer heuristics

### Changed
- Phase 1 now includes Entry Point Classification table, Access Control Classification heuristic, and Quick Maturity Assessment
- Phase 2 Perspective 1 (Attacker) now includes unchecked `&signer` scan (Aptos) and PTB-composability check (Sui)
- Phase 2 now has 4 perspectives (added Symmetry Checker)
- DEFI-54 now includes Sui PTB amplification guidance
- DESIGN-L1 now includes caveat about missing tolerance checks

### Benchmark
- v2.3.0 found 2/6 known CurrentSUI bugs
- v3.0.0 target: 4/6 known bugs + 2 novel bugs (close factor bypass, limiter reset) that v2.3.0 missed

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
