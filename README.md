# move-auditor

> Claude Code / Cursor skill for Move smart contract security auditing — Sui & Aptos.
> Built by [Panther Audits](https://github.com/pantheraudits).

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/license/mit/)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](CONTRIBUTING.md)

---

## What is this?

A structured Claude Code / Cursor skill that gives **fast, automatic security feedback** on Move smart contracts as you develop or audit. No prompts to copy-paste, no placeholders to fill.

When you open a `.move` file or ask Claude to review Move code, the skill activates and runs a systematic audit covering:

- **Common Move vulnerabilities** — access control, arithmetic, resource safety, logic errors
- **Sui-specific patterns** — object ownership, shared object reentrancy, witness abuse, dynamic fields, hot potato misuse
- **Aptos-specific patterns** — resource accounts, coin type confusion, table safety, module upgrades, `acquires` correctness
- **DeFi attack vectors** — oracle manipulation, flash loans, AMM manipulation, liquidation bugs, slippage, governance attacks

---

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

**For Cursor:**
```bash
mkdir -p ~/.cursor/skills
cp -r move-auditor ~/.cursor/skills/move-auditor
```

---

## Usage

The skill **auto-activates** when `.move` files are present or when you ask about Move security. It will:

1. Detect chain (Sui or Aptos) automatically
2. Map the codebase structure
3. Run a full vulnerability scan
4. Produce a structured audit report with severity, location, PoC scenario, and fix

You can also invoke it explicitly:

```
/move-auditor         # Full audit of all .move files in scope
/move-auditor [file]  # Audit a specific file
```

---

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

---

## Disclaimer

AI-assisted audit output **must be manually verified**. This skill accelerates your workflow — it does not replace deep manual review and PoC testing. All findings require human confirmation before being included in any report.

---

## Roadmap

- [ ] Vulnerability database (real-world Move CVEs and contest findings)
- [ ] Sui DeFi protocol-specific patterns (Cetus, Aftermath, Turbos)
- [ ] Aptos DeFi protocol-specific patterns (Thala, Aries, Echelon)
- [ ] Automated grep patterns for common Move anti-patterns
- [ ] Report templates for private audits vs. contest submissions

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Contact

Panther Audits — [@pantheraudits](https://github.com/pantheraudits)
