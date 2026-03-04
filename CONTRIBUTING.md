# Contributing

Contributions are welcome — new vulnerability checks, real-world findings, improved patterns,
and chain-specific updates all help make this skill more useful for the Move security community.

---

## Adding a new check

1. Fork the repo and create a branch: `git checkout -b add/SUI-11-xyz`
2. Add your check to the appropriate reference file with:
   - A numbered ID (`SUI-11`, `APT-12`, `DEFI-11`, or a new section in `common-move.md`)
   - Vulnerable code pattern (with comment `// VULNERABLE`)
   - Safe code pattern (with comment `// SAFE`)
   - Risk description and attack scenario
   - Check instructions for the auditor
3. Add the check to the verification checklist at the bottom of the file
4. If based on a real finding: link to the report or contest submission
5. Open a PR with a clear description of what the check catches and why it matters

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
