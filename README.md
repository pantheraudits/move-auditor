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

1. Detect chain (Sui or Aptos) automatically
2. Map the codebase structure
3. Run a full vulnerability scan
4. Produce a structured audit report with severity, location, PoC scenario, and fix

**Read the full write-up:** [The Move Auditor — Blog Post](https://pantheraudits.com/blog/the-move-auditor.html)


## Skill Structure

```
move-auditor/
├── SKILL.md                     # Orchestrator — workflow, phases, report format
├── common-move.md               # Chain-agnostic Move security checks + checklist
├── sui-patterns.md              # Sui-specific vulnerability patterns (SUI-01 to SUI-10)
├── aptos-patterns.md            # Aptos-specific vulnerability patterns (APT-01 to APT-11)
├── defi-vectors.md              # DeFi attack vectors for Move protocols
├── audit-prompts.md             # Deep-dive prompts + vulnerability pattern pack
└── sample-finding.md            # Example audit output showing expected format
```

Reference files are loaded **on demand** — the agent reads them when the chain is detected,
keeping the initial context window lean.


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
