# Changelog

All notable changes to `move-auditor` are documented here.

Versioning follows [Semantic Versioning](https://semver.org/):
- **MAJOR** — breaking changes to skill interface or report format
- **MINOR** — new checks, new reference files, expanded coverage
- **PATCH** — fixes to existing checks, wording improvements, bug corrections

Each release is tagged as `move-auditor@X.Y.Z`.

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
