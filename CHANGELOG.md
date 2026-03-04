# Changelog

All notable changes to `move-auditor` are documented here.

Versioning follows [Semantic Versioning](https://semver.org/):
- **MAJOR** — breaking changes to skill interface or report format
- **MINOR** — new checks, new reference files, expanded coverage
- **PATCH** — fixes to existing checks, wording improvements, bug corrections

Each release is tagged as `move-auditor@X.Y.Z`.

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
