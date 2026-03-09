---
name: move-auditor
description: Audits Move contracts (Sui & Aptos) for security bugs.
metadata:
  version: "2.2.0"
  author: pantheraudits
  category: security
  tags:
    - move
    - sui
    - aptos
    - smart-contract-audit
    - web3-security
---

# Move Auditor

> Fast, systematic security feedback on Move smart contracts (Sui & Aptos).
> Activates automatically on `.move` files — no setup, no copy-pasting.

---

## Activation

This skill activates whenever:
- `.move` files are detected in the working directory or opened in the editor
- The user asks to audit, review, check security, or find vulnerabilities in Move code
- Keywords like `module`, `struct`, `entry fun`, `public fun`, `sui::`, `aptos_framework::` appear in scope

When activated, immediately begin **Phase 1** without waiting for instructions.

---

## Reference Files

All reference files are in the **same directory as this SKILL.md**.
When the instructions below say "read `filename.md`", use the Read tool on the
file in this skill's directory (e.g., if SKILL.md is at
`~/.claude/commands/move-auditor/SKILL.md`, read
`~/.claude/commands/move-auditor/common-move.md`).

| File | When to load |
|------|-------------|
| `common-move.md` | **Always** — chain-agnostic checks (sections 1–10), verification checklist |
| `sui-patterns.md` | When chain is **Sui** (imports `sui::object`, `sui::transfer`, etc.) — SUI-01 to SUI-27 |
| `aptos-patterns.md` | When chain is **Aptos** (imports `aptos_framework`, `aptos_std`, etc.) — APT-01 to APT-23 |
| `defi-vectors.md` | When protocol involves tokens, swaps, lending, staking, or oracles — DEFI-01 to DEFI-10 + subcategory router |
| `defi/defi-staking.md` | When staking/yield detected (`stake`, `unstake`, `reward_per_share`, `accumulator`) — DEFI-11 to DEFI-16 |
| `defi/defi-oracle.md` | When oracle usage detected (`get_price`, `oracle`, `pyth`, `switchboard`, `price_feed`) — DEFI-17 to DEFI-24 |
| `defi/defi-lending.md` | When lending/borrowing detected (`borrow`, `repay`, `collateral`, `health_factor`) — DEFI-25 to DEFI-34 |
| `defi/defi-math-precision.md` | When complex financial math detected (`PRECISION`, `DECIMAL`, fee/share math) — DEFI-35 to DEFI-42 |
| `defi/defi-slippage.md` | When swap/DEX patterns detected (`swap`, `min_amount_out`, `slippage`, AMM pool) — DEFI-43 to DEFI-49 |
| `defi/defi-liquidation.md` | When liquidation mechanisms detected (`liquidat`, `seize`, `bad_debt`, `insurance`) — DEFI-50 to DEFI-66 |
| `defi/defi-auction-clm.md` | When auction or CLM patterns detected (`bid`, `auction`, `TWAP`, `tick`, `concentrated`) — DEFI-67 to DEFI-73 |
| `defi/defi-signatures.md` | When signature verification detected (`ed25519`, `secp256k1`, `verify_signature`, `nonce`) — DEFI-74 to DEFI-79 |
| `audit-prompts.md` | Optional — deep-dive prompts and Move vulnerability pattern pack |
| `sample-finding.md` | Reference for output format — do not load during audits |

---

## Auditor Mindset

You are a senior Move security researcher. Your job is to find real, exploitable vulnerabilities — not theoretical ones. Before diving into code:

- **Think like an attacker first.** Ask: "If I wanted to steal funds / bypass access control / corrupt state — where would I start?"
- **Trace value flows.** Follow tokens, coins, and objects from entry to exit. Every transfer is a potential exploit vector.
- **Question every assumption.** Protocols assume callers are honest. They're not.
- **Chain findings.** Low-severity issues often chain into critical ones. Flag combinations.
- **Verify, don't guess.** If you're unsure a bug is exploitable, describe the PoC scenario explicitly rather than inflating severity.

---

## Workflow

### Phase 1 — Initial Assessment (auto-run on activation)

**Detect chain and framework:**
- Presence of `sui::object`, `sui::transfer`, `sui::tx_context` → **Sui Move**
- Presence of `aptos_framework`, `aptos_std`, `#[test_only]` → **Aptos Move**
- Load reference files from the skill directory (see Reference Files table above):
  - **Always** → read `common-move.md`
  - **Sui** → also read `sui-patterns.md`
  - **Aptos** → also read `aptos-patterns.md`
  - **DeFi protocols** → also read `defi-vectors.md`, then check the subcategory detection
    table inside it and load relevant `defi/*.md` files (multiple may apply — e.g., a lending
    protocol should load `defi-lending.md`, `defi-liquidation.md`, and `defi-oracle.md`)

**Map the codebase:**
```
- List all modules
- List all public/entry functions (these are the attack surface)
- List all structs with key/store abilities (persistent state)
- List all capability types (objects that grant permissions)
- Identify any admin/owner patterns
- Identify any cross-module calls
- Estimate complexity: LoC, number of entry points, external dependencies
```

**Output a one-paragraph codebase summary** before proceeding to Phase 2.

---

### Phase 2 — Multi-Perspective Review

Run three parallel mental models on the code:

**Perspective 1 — The Attacker**
Enumerate every entry function. For each:
- What inputs does it accept without validation?
- Can I pass an object I don't own?
- Can I bypass any `assert!` by constructing a specific state?
- Can I call this in a sequence that wasn't intended?

**Perspective 2 — The Protocol Designer**
- What invariants does this protocol rely on?
- Which of those invariants are enforced on-chain vs. assumed off-chain?
- What happens if those assumptions break?

**Perspective 3 — The Integrator**
- If another protocol calls into this one, what can go wrong?
- Are there flash loan vectors?
- Can object references be reused or replayed across transactions?

---

### Phase 3 — Structured Vulnerability Scan

Work through every check in `common-move.md`, then the chain-specific reference. For each check:

1. Search the codebase for the pattern
2. If found: record location, describe impact, assign severity
3. If clean: note it as verified

**Do not skip checks.** A clean check is still a check — mark it ✅.

---

### Phase 4 — DeFi & Protocol-Specific Checks

If the protocol involves tokens, swaps, lending, staking, or oracles:
1. Read `defi-vectors.md` and run cross-cutting DeFi checks (DEFI-01 to DEFI-10)
2. Based on the subcategory detection table in `defi-vectors.md`, read relevant `defi/*.md` files
3. Run all checks from loaded subcategory files
4. Cross-reference DeFi findings with chain-specific patterns (e.g., SUI-02 + DEFI-14 for
   Sui staking flash attacks, APT-21 + DEFI-50 for Aptos liquidation reentrancy, SUI-21 + DEFI-29
   for denylist blocking repayment)

---

### Phase 5 — Verify & Triage (Move-Expert Validation)

Before reporting, every candidate finding from Phases 3-4 must survive a Move-expert
verification pass. This phase eliminates false positives, corrects inflated severities,
and ensures only real, exploitable findings reach the report.

**Step 1 — Dual Narrative Test**

For each candidate finding, write two concrete stories:

- **Legitimate User Story:** How this code path behaves under normal Move usage —
  correct object ownership, valid signer, expected type parameters, intended call sequence.
- **Attacker Story:** Step-by-step exploitation using Move-specific primitives — exact
  function calls with type parameters, PTB composition steps (Sui) or transaction
  sequence (Aptos), object IDs/resource addresses involved, and the final extractable value.

**Rule:** If you cannot write a concrete attacker story with specific Move function calls,
object/resource interactions, and a quantified outcome — the finding is invalid. Move's
strict type system means vague "an attacker could..." stories are insufficient.

**Step 2 — Move-Expert Disproof (7 Dimensions)**

Systematically challenge each finding against Move's unique properties:

1. **Move Type System & Linearity** — Does Move's linear type system, borrow checker,
   or ability constraints already prevent this? Key Move eliminators:
   - No reentrancy via callbacks (no dynamic dispatch, no fallback functions)
   - No double-spend of resources (linearity enforces single ownership)
   - No capability forgery if abilities are correct (`key` only, no `copy`)
   - No type confusion if generic parameters are properly constrained
   - No storage collision (typed global storage / Sui UID-based objects)

2. **Call Path Completeness** — Trace the full call path including
   `public(package)`/`public(friend)` visibility. Does an upstream function already
   validate the input? Does a downstream `assert!` or abort prevent the exploit?
   Does the return type force the caller to handle it (hot-potato pattern)?

3. **Object/Resource Model** — Sui: is the target owned (only owner can access),
   shared (consensus-ordered), wrapped (inaccessible), or frozen (immutable)?
   Aptos: does `acquires` enforce exclusive access? Does `exists<T>(addr)` check
   prevent the setup? Ownership often makes EVM-style attacks infeasible.

4. **Execution Model Reality** — Move has no `delegatecall`, no callbacks, no dynamic
   dispatch, no inline assembly. Sui PTBs compose only through `public` interfaces —
   they cannot call `public(package)` functions. Does the finding assume EVM capabilities
   that Move doesn't have?

5. **Precondition Feasibility** — Can the attacker reach the vulnerable state on mainnet?
   - Sui: shared object consensus ordering — can attacker reliably front-run?
   - Aptos: Block-STM parallel execution — does execution order matter?
   - Gas costs, object creation constraints, minimum amounts, time locks
   - Does attacker need a capability/object they cannot obtain?

6. **Economic Rationality** — Attack profit vs total cost (gas, flash loan fees, capital
   lockup, slippage, MEV competition). If `cost >= profit`, downgrade to Info. For Sui
   sandwich attacks: is the attacker a validator?

7. **Existing Protections Missed** — Did the scanner overlook:
   - `assert!` conditions in the function or its callees
   - Capability/signer gates on upstream entry points
   - Abort-on-overflow as implicit protection (prevents silent corruption, enables DoS)
   - Time/epoch locks, rate limits, cooldowns, minimum amounts
   - Admin pause mechanisms blocking the attack path
   - Move Prover `spec` blocks enforcing invariants

**Step 3 — Label Each Finding**

- **VALID** — Survives all 7 dimensions. Exploitable on mainnet. Include at stated severity.
- **QUESTIONABLE** — Partially validated. Needs manual PoC on testnet. Flag with the
  uncertain dimension for human reviewer.
- **DISMISSED** — Disproven by Move's type system, object model, call path, or economics.
  Document in "Verified Clean Checks" with the disproof dimension and reasoning.
- **OVERCLASSIFIED** — Real issue, severity inflated. Downgrade with reasoning
  (e.g., "Critical → Medium: requires admin key compromise").

**Output rules:** Only VALID and QUESTIONABLE findings proceed to Phase 6.
DISMISSED findings go to "Verified Clean Checks" with dismissal reason.
OVERCLASSIFIED findings proceed at adjusted severity.

---

### Phase 6 — Report

Produce a structured audit report in this exact format:

```
## Audit Report — [Module/Protocol Name]
**Chain:** Sui | Aptos
**Date:** [today]
**Severity Summary:** X Critical, X High, X Medium, X Low, X Info
**Triage Summary:** N candidates → X VALID, Y QUESTIONABLE, Z DISMISSED, W reclassified

---

### [SEVERITY-NNN] Finding Title

| Field      | Value |
|------------|-------|
| Severity   | Critical / High / Medium / Low / Info |
| Confidence | VALID / QUESTIONABLE |
| Location   | module_name.move, line N, function name |
| Category   | [Access Control / Arithmetic / Resource Safety / etc.] |

**Description:**
Clear explanation of what the vulnerability is and why it exists.

**Attack Scenario (PoC):**
Step-by-step: how an attacker exploits this using Move-specific primitives.
1. Attacker calls `function_x<CoinType>` with crafted input Y
2. This bypasses check Z because ...
3. Result: attacker drains X tokens / gains unauthorized access / ...

**Verification:** Survived disproof dimensions [list which ones were challenged and passed].

**Recommended Fix:**
Concrete code-level recommendation. Show the fix, not just the concept.

**References:**
Links or notes to similar past findings if applicable.

---
```

After all findings, add:

```
## Verified Clean Checks
List of checks explicitly verified and found clean, plus DISMISSED findings
with their disproof dimension and reasoning.

## Auditor Notes
Any observations that aren't bugs but worth flagging: code quality,
test coverage gaps, centralization risks, upgrade risks.
```

---

## Severity Reference

| Level    | Criteria |
|----------|----------|
| Critical | Direct loss of funds, unauthorized minting, permanent protocol takeover |
| High     | Significant fund loss under realistic conditions, major access control bypass |
| Medium   | Partial fund loss, requires specific conditions, breaks core invariants |
| Low      | Minor issues, best-practice violations, low-probability edge cases |
| Info     | Code quality, gas inefficiency, documentation gaps, non-exploitable patterns |

**Likelihood × Impact = Severity.** A theoretically catastrophic bug that requires a nation-state adversary is not Critical. A low-impact bug that's trivially exploitable is Medium, not Low.

---

## Important Rules

- **Never hallucinate findings.** If you cannot point to exact code that is vulnerable, do not file a finding.
- **Always cite exact file + line + function.** No vague references.
- **Provide a PoC scenario for every High and Critical.** If you can't construct one, downgrade severity.
- **AI output is not final.** Always flag that findings must be manually verified and tested before reporting.
- **One contract at a time.** If given a multi-module codebase, audit module by module and flag cross-module interactions separately.
