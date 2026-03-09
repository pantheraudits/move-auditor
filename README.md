# move-auditor

> Claude Code skill for Move smart contract security auditing — Sui & Aptos.
> Built by [Panther](https://x.com/thepantherplus).

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/license/mit/)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](CONTRIBUTING.md)

## What is this?

A skill you plug into Claude Code that turns it into a Move (Sui & Aptos) smart contract security auditor — battle-tested vulnerability patterns drawn from real-world exploits, ready to hunt bugs the moment you open a `.move` file.

## Install

```bash
# Clone and install to Claude Code
git clone https://github.com/pantheraudits/move-auditor.git
mkdir -p ~/.claude/commands
cp -r move-auditor ~/.claude/commands/move-auditor
```

**Update to latest:**
```bash
cd move-auditor && git pull
cp -r . ~/.claude/commands/move-auditor
```


## Usage

> **Important:** `/move-auditor` is a slash command inside Claude Code — not a terminal command.
> You must run it from within a Claude Code session, not from your shell (zsh/bash).

### Quick start

1. Open your terminal and navigate to your Move project:
   ```bash
   cd /path/to/your-move-project
   ```
2. Start a Claude Code session:
   ```bash
   claude
   ```
3. Inside the Claude Code session, run the slash command:
   ```
   /move-auditor         # Full audit of all .move files in scope
   /move-auditor [file]  # Audit a specific file
   ```

The skill also **auto-activates** when `.move` files are present or when you ask about Move security. It will:

1. Detect chain (Sui or Aptos) and load relevant patterns
2. Map the codebase structure and attack surface
3. Run a full vulnerability scan (130+ patterns across chain-agnostic, chain-specific, and DeFi checks)
4. Verify & triage every finding through a Move-expert validation pass (7 disproof dimensions)
5. Produce a structured audit report with severity, confidence, PoC scenario, and fix

**Read the full write-up:** [The Move Auditor — Blog Post](https://pantheraudits.com/blog/the-move-auditor.html)


## Skill Structure

```
move-auditor/
├── SKILL.md                     # Orchestrator — 6-phase workflow with verify & triage
├── common-move.md               # Chain-agnostic Move security checks + checklist
├── sui-patterns.md              # Sui-specific patterns (SUI-01 to SUI-27)
├── aptos-patterns.md            # Aptos-specific patterns (APT-01 to APT-23)
├── defi-vectors.md              # DeFi attack vectors (DEFI-01 to DEFI-10) + subcategory router
├── defi/
│   ├── defi-staking.md          # Staking/yield patterns (DEFI-11 to DEFI-16)
│   ├── defi-oracle.md           # Oracle patterns (DEFI-17 to DEFI-24)
│   ├── defi-lending.md          # Lending/borrowing patterns (DEFI-25 to DEFI-34)
│   ├── defi-math-precision.md   # Math & precision patterns (DEFI-35 to DEFI-42)
│   ├── defi-slippage.md         # Slippage & DEX patterns (DEFI-43 to DEFI-49)
│   ├── defi-liquidation.md      # Liquidation patterns (DEFI-50 to DEFI-66)
│   ├── defi-auction-clm.md      # Auction & CLM patterns (DEFI-67 to DEFI-73)
│   └── defi-signatures.md       # Signature patterns (DEFI-74 to DEFI-79)
├── audit-prompts.md             # Deep-dive prompts + vulnerability pattern pack
└── sample-finding.md            # Example audit output showing expected format
```

Reference files are loaded **on demand** — the agent reads only what's relevant to the
detected chain and protocol type, keeping the initial context window lean.


## Disclaimer

AI-assisted audit output **must be manually verified**. This skill accelerates your workflow — it does not replace deep manual review and PoC testing. All findings require human confirmation before being included in any report.


## Roadmap

- [ ] Vulnerability database (real-world Move CVEs and contest findings)
- [ ] Sui DeFi protocol-specific patterns (Cetus, Aftermath, Turbos)
- [ ] Aptos DeFi protocol-specific patterns (Thala, Aries, Echelon)
- [ ] Automated grep patterns for common Move anti-patterns
- [ ] Report templates for private audits vs. contest submissions
- [ ] Benchmarking the skill against baseline prompts and manual review to see where it actually makes a difference 

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Contact

Panther Audits — [GitHub](https://github.com/pantheraudits) · [Telegram](https://t.me/theblackpantherhere) · [X](https://x.com/thepantherplus)
