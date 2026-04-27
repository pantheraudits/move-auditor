<p align="center">
  <strong>move-auditor</strong><br>
  <em>Claude Code skill for Move smart contract security auditing</em>
</p>

<p align="center">
  <a href="https://opensource.org/license/mit/"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
  <a href="CONTRIBUTING.md"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg" alt="Contributions Welcome"></a>
  <img src="https://img.shields.io/badge/version-3.6.1-blue.svg" alt="Version 3.6.1">
  <img src="https://img.shields.io/badge/patterns-180%2B-red.svg" alt="180+ Patterns">
  <img src="https://img.shields.io/badge/chains-Sui%20%7C%20Aptos-purple.svg" alt="Sui | Aptos">
</p>

<p align="center">
  Built by <a href="https://x.com/thepantherplus">Panther</a>
</p>

---

A skill you plug into [Claude Code](https://docs.anthropic.com/en/docs/claude-code) that turns it into a Move (Sui & Aptos) smart contract security auditor — battle-tested vulnerability patterns drawn from real-world exploits, ready to hunt bugs the moment you open a `.move` file.

**Read the full write-up:** [The Move Auditor — Blog Post](https://pantheraudits.com/blog/the-move-auditor.html)

---

## Features

- **180+ vulnerability patterns** across chain-agnostic, Sui-specific, Aptos-specific, and DeFi checks
- **Auto-activates** on `.move` files — no setup, no slash commands needed
- **8-phase audit workflow** — from codebase mapping to verified, triaged report
- **Anti-false-positive engine** — confidence gating, evidence chains, FP catalog, and self-hallucination checks
- **Build & test log analysis** — catches arithmetic aborts, assertion failures, and `#[expected_failure]` anomalies
- **Signal-based coverage routing** — detects protocol type and loads only relevant patterns
- **DeFi deep-dive** — 87 patterns covering staking, oracles, lending, liquidation, slippage, auctions, and signatures
- **Semantic gap detection** — stale state, accumulator drift, cross-module accounting desync
- **Real-world validated** — findings accepted into production codebases (see below)

---

## Install

```bash
git clone https://github.com/pantheraudits/move-auditor.git
mkdir -p ~/.claude/commands
cp -r move-auditor ~/.claude/commands/move-auditor
```

**Update to latest:**
```bash
cd move-auditor && git pull
cp -r . ~/.claude/commands/move-auditor
```

---

## Usage

> `/move-auditor` is a slash command inside Claude Code — not a terminal command.
> Run it from within a Claude Code session.

### Quick start

```bash
# 1. Navigate to your Move project
cd /path/to/your-move-project

# 2. Start Claude Code
claude

# 3. Inside the session, run:
/move-auditor              # Full audit of all .move files in scope
/move-auditor [file]       # Audit a specific file
```

### Best results

For the deepest analysis, run the skill against a **buildable project** — one where
`sui move build` (Sui) or `aptos move compile` (Aptos) succeeds. The auditor will run
the test suite, capture logs, and analyze them for arithmetic aborts, assertion failures,
and suspicious `#[expected_failure]` annotations that may indicate latent High/Critical
bugs invisible to static-only review.

> **Static-only mode:** If the project doesn't build (missing deps, partial code, review-only
> context), the skill still runs the full pattern-based audit — it just skips test log analysis.

---

## How It Works

The skill runs an **8-phase pipeline** on every audit:

```
Phase 1  Detect chain, map codebase, classify entry points, build coverage plan
     |
Phase 2  Multi-perspective review (Attacker, Designer, Integrator, Symmetry,
         Bidirectional Admin, Consistency)
     |
Phase 3  Structured vulnerability scan — every check in every loaded reference file
     |
Phase 4  DeFi & protocol-specific deep-dive (87 subcategory patterns)
     |
Phase 5  Semantic gap & stale-state scan (accumulators, checkpoints, cross-module drift)
     |
Phase 6  Cross-module interaction scan (9 mandatory interaction pairs)
     |
Phase 7  Verify & triage — Move-expert validation, dual narrative test, 8-dimension
         disproof, kill questions, evidence chains, confidence gating
     |
Phase 8  Structured audit report with severity, confidence, PoC, and fix
```

Reference files are loaded **on demand** — the agent reads only what's relevant to the
detected chain and protocol type, keeping the context window lean.

---

## Pattern Coverage

| Category | File | Patterns |
|----------|------|----------|
| Chain-agnostic | `common-move.md` | Access control, arithmetic, resource safety, logic, input validation, cross-module, upgradeability, build/test analysis |
| Sui-specific | `sui-patterns.md` | SUI-01 to SUI-44 |
| Aptos-specific | `aptos-patterns.md` | APT-01 to APT-25 |
| DeFi cross-cutting | `defi-vectors.md` | DEFI-01 to DEFI-10 |
| Staking & yield | `defi/defi-staking.md` | DEFI-11 to DEFI-16 |
| Oracles | `defi/defi-oracle.md` | DEFI-17 to DEFI-24 |
| Lending & borrowing | `defi/defi-lending.md` | DEFI-25 to DEFI-34, DEFI-80, DEFI-82, DEFI-84 |
| Math & precision | `defi/defi-math-precision.md` | DEFI-35 to DEFI-42, DEFI-85 to DEFI-87 |
| Slippage & MEV | `defi/defi-slippage.md` | DEFI-43 to DEFI-49 |
| Liquidation | `defi/defi-liquidation.md` | DEFI-50 to DEFI-66, DEFI-81, DEFI-83 |
| Auctions & CLM | `defi/defi-auction-clm.md` | DEFI-67 to DEFI-73 |
| Signatures | `defi/defi-signatures.md` | DEFI-74 to DEFI-79 |

---

## Skill Structure

```
move-auditor/
├── SKILL.md                          # Orchestrator — 8-phase workflow, coverage routing
│
├── common-move.md                    # Chain-agnostic checks + verification checklist
├── sui-patterns.md                   # Sui-specific patterns (SUI-01 to SUI-44)
├── aptos-patterns.md                 # Aptos-specific patterns (APT-01 to APT-25)
│
├── checklist-router.md               # Signal-based coverage planner & file router
├── verification-policy.md            # Evidence hierarchy, feasibility gates, severity discipline
├── semantic-gap-checks.md            # Stale-state, accumulator, cross-module desync checks
│
├── move-fp-catalog.md                # Anti-FP: rationalizations to reject, FP catalog
├── evidence-chains.md                # Structured evidence templates (Phase 7)
├── confidence-gates.md               # Confidence gating, hard evidence requirements (Phase 7)
│
├── defi-vectors.md                   # DeFi attack vectors (DEFI-01 to DEFI-10) + router
├── defi/
│   ├── defi-staking.md               # Staking/yield (DEFI-11 to DEFI-16)
│   ├── defi-oracle.md                # Oracles (DEFI-17 to DEFI-24)
│   ├── defi-lending.md               # Lending/borrowing (DEFI-25 to DEFI-34, 80, 82, 84)
│   ├── defi-math-precision.md        # Math & precision (DEFI-35 to DEFI-42, 85-87)
│   ├── defi-slippage.md              # Slippage & DEX (DEFI-43 to DEFI-49)
│   ├── defi-liquidation.md           # Liquidation (DEFI-50 to DEFI-66, 81, 83)
│   ├── defi-auction-clm.md           # Auctions & CLM (DEFI-67 to DEFI-73)
│   ├── defi-signatures.md            # Signatures (DEFI-74 to DEFI-79)
│   └── defi-lending-design-patterns.md  # Known-good patterns (DESIGN-L1 to L4)
│
├── audit-prompts.md                  # Deep-dive prompts & vulnerability pattern pack
├── sample-finding.md                 # Example audit output format
│
└── benchmarks/
    ├── BENCHMARK.md                  # Benchmarking methodology
    ├── BENCHMARK-openzeppelin.md     # OpenZeppelin contracts-sui benchmark
    └── BENCHMARK-currensui.md        # CurrenSui lending protocol benchmark
```

---

## Real-World Impact

Bugs found by `move-auditor` have been accepted into production codebases, contest leaderboards, and paid bug bounties. In every case the skill surfaced the *candidate* finding — a human auditor reproduced, narrowed, and wrote up the bug before submission.

| Context | Finding | Outcome |
|---------|---------|---------|
| Aptos perps protocol (private bug bounty, name withheld) | Candidate High-severity finding (originally triaged as Critical, downgraded to High by the program) plus 1 confirmed Medium already paid. Additional High and Medium findings accepted as valid and in triage. Surfaced with `move-auditor`, reproduced and written up manually by [Panther](https://x.com/thepantherplus). | **20,000 USDC (1 High) + 1 Medium paid** — further awards pending triage |
| [Current Finance](https://audits.sherlock.xyz/contests/current-finance) — Sherlock contest, Sui Move lending protocol | 1 High + 2 Medium confirmed findings: opposite-direction EMA/spot deviations creating unliquidatable positions, ADL using reserve-level instead of emode-group-level debt, deposit cap double-subtraction bypass. Identified with `move-auditor`, manually verified by [Panther](https://x.com/thepantherplus). | **#27 out of 170+ participants** |
| [OpenZeppelin Contracts for Sui](https://github.com/OpenZeppelin/contracts-sui) | Missing `EDivideByZero` guard in fixed-point `div`/`mod` — relied on opaque VM abort instead of descriptive error | [PR #263](https://github.com/OpenZeppelin/contracts-sui/pull/263) **Merged** |
| Sui DeFi margin protocol (bug bounty, name withheld) | Missing post-trade health check in margin trading proxy — leveraged accounts can keep trading after becoming liquidatable, enabling value extraction to a second account and leaving bad debt for lenders | **Confirmed** (duplicate of prior report) |
| Multiple Sui & Aptos protocols (bug bounties, names withheld) | Several additional findings across Sui and Aptos programs surfaced by `move-auditor` and manually reproduced and written up by [Panther](https://x.com/thepantherplus) | **In triage** — awards pending |

> The OpenZeppelin find was a unique result from [benchmarking](benchmarks/BENCHMARK-openzeppelin.md) — no other AI audit tool (MAIA, Raw Claude CLI) caught it.
>
> **How to read this table**: `move-auditor` is a *candidate generator*, not a proof system. Each row represents a bug a human auditor reproduced, triaged, and submitted. The skill narrows where to look; the auditor still does the reading, the PoC, and the write-up.

---

## Benchmarks

The skill is [benchmarked](benchmarks/BENCHMARK.md) against baseline prompts (raw Claude, MAIA) and manual review to measure where it actually makes a difference. Benchmark results drove multiple improvements:

- **v2.3.0 → v3.0.0**: CurrenSui detection improved from 2/6 to 4/6 known bugs + 2 novel findings
- **v3.4.0**: Anti-FP overhaul reduced false positive rate after [CurrenSui benchmark](benchmarks/BENCHMARK-currensui.md) revealed ~25% FP rate
- **v3.5.0**: 16 new Sui patterns from design-level anti-pattern analysis
- **v3.6.x**: Patterns validated against Current Finance contest — 1 High + 2 Medium confirmed, #27 placement

---

## Roadmap

- [ ] Vulnerability database (real-world Move CVEs and contest findings)
- [ ] Sui DeFi protocol-specific patterns (Cetus, Aftermath, Turbos)
- [ ] Aptos DeFi protocol-specific patterns (Thala, Aries, Echelon)
- [ ] Automated grep patterns for common Move anti-patterns
- [ ] Machine-readable audit artifacts (`coverage-plan`, validated findings, structured clean checks)
- [ ] Report templates for private audits vs. contest submissions
- [x] Benchmarking against baseline prompts and manual review

---

## Disclaimer

AI-assisted audit output **must be manually verified**. This skill accelerates your workflow — it does not replace deep manual review and PoC testing. All findings require human confirmation before being included in any report.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Contact

Panther Audits — [GitHub](https://github.com/pantheraudits) · [Telegram](https://t.me/theblackpantherhere) · [X](https://x.com/thepantherplus)
