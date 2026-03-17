# Contributing

Contributions are welcome — new vulnerability checks, real-world findings, improved patterns,
and chain-specific updates all help make this skill more useful for the Move security community.

---

## Adding a new check

1. Fork the repo and create a branch: `git checkout -b add/SUI-11-xyz`
2. Determine the correct file for your check:
   - **Common Move checks** → `common-move.md`
   - **Sui-specific** → `sui-patterns.md` (SUI-XX)
   - **Aptos-specific** → `aptos-patterns.md` (APT-XX)
   - **DeFi cross-cutting** → `defi-vectors.md` (DEFI-01 to DEFI-10)
   - **DeFi subcategory** → `defi/defi-<category>.md` (DEFI-11+, see table below)
3. Add your check with:
   - A numbered ID (next available: SUI-29, APT-25, DEFI-87)
   - Vulnerable code pattern (with comment `// VULNERABLE`)
   - Safe code pattern (with comment `// SAFE`)
   - Risk description and attack scenario
   - Check instructions for the auditor
4. Add the check to the verification checklist at the bottom of the file
5. If based on a real finding: link to the report or contest submission
6. Open a PR with a clear description of what the check catches and why it matters

### DeFi subcategory file guide

| Category | File | Current IDs |
|----------|------|-------------|
| Staking / Yield | `defi/defi-staking.md` | DEFI-11 to DEFI-16 |
| Oracle | `defi/defi-oracle.md` | DEFI-17 to DEFI-24 |
| Lending / Borrowing | `defi/defi-lending.md` | DEFI-25 to DEFI-34, DEFI-80, DEFI-82, DEFI-84 |
| Math / Precision | `defi/defi-math-precision.md` | DEFI-35 to DEFI-42, DEFI-85, DEFI-86 |
| Slippage / MEV | `defi/defi-slippage.md` | DEFI-43 to DEFI-49 |
| Liquidation | `defi/defi-liquidation.md` | DEFI-50 to DEFI-66, DEFI-81, DEFI-83 |
| Auction / CLM | `defi/defi-auction-clm.md` | DEFI-67 to DEFI-73 |
| Signatures | `defi/defi-signatures.md` | DEFI-74 to DEFI-79 |

New DeFi checks should use the next sequential ID (DEFI-87+) and go in the matching subcategory file. If no subcategory fits, create a new `defi/defi-<category>.md` file and register it in `SKILL.md` and `defi-vectors.md`.

---

## Adding a real-world finding

Found a Move vulnerability in a public audit report or contest? Add it to the vulnerability database
(coming soon: `references/vuln-db.md`). Format:

```markdown
### [VULN-NNN] Finding Title
**Source:** Contest/protocol name, date, link
**Chain:** Sui / Aptos
**Category:** Access Control / Arithmetic / etc.
**Summary:** One-paragraph description of the bug
**Pattern:** Code snippet showing the vulnerable pattern
**Fix:** What was done to fix it
```

---

## PR checklist

- [ ] Check is in the correct reference file
- [ ] Check has a numbered ID
- [ ] Vulnerable and safe code examples included
- [ ] Added to verification checklist
- [ ] `SKILL.md` line count still under 500
- [ ] If adding a new reference file: referenced from `SKILL.md`

---

## License

By contributing, you agree your contributions are licensed under MIT.
