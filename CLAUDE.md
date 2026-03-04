# CLAUDE.md

Instructions for Claude when working inside the `move-auditor` repository.

---

## What this repo is

This is a Claude Code / Cursor skill for auditing Move smart contracts on Sui and Aptos.
The skill lives in `move-auditor/` and is installed by copying that directory to
`~/.claude/commands/move-auditor` or `~/.cursor/skills/move-auditor`.

---

## When contributing checks or patterns

1. **New common checks** go in `move-auditor/common-move.md`
2. **Sui-specific checks** go in `move-auditor/sui-patterns.md` — numbered `SUI-XX`
3. **Aptos-specific checks** go in `move-auditor/aptos-patterns.md` — numbered `APT-XX`
4. **DeFi vectors** go in `move-auditor/defi-vectors.md` — numbered `DEFI-XX`
5. **New reference files** (e.g., a vulnerability database) go in `move-auditor/`
   and must be referenced from `SKILL.md` with a load instruction

---

## Version tagging

Releases are tagged as `move-auditor@X.Y.Z` matching `metadata.version` in `SKILL.md`.

Before tagging a release:
1. Update `metadata.version` in `move-auditor/SKILL.md`
2. Add a changelog entry in `CHANGELOG.md`
3. Tag: `git tag move-auditor@X.Y.Z && git push --tags`

---

## File size limits

- `SKILL.md` must stay under 500 lines (this is the always-loaded context)
- Reference files can be longer — they are loaded on demand
- If a reference file exceeds ~400 lines, split into sub-files

---

## Do not

- Add Solidity-specific, EVM-specific, or Rust/Anchor-specific content
- Add placeholders that require manual editing before use
- Add checks without a code example showing vulnerable and safe patterns
