---
name: move-auditor
description: Audits Move contracts (Sui & Aptos) for security bugs.
metadata:
  version: "3.6.0"
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

## When NOT to Use

- Non-Move contracts (Solidity, Rust/Anchor, EVM, TEAL, FunC)
- General code review for style, performance, or refactoring
- Writing Move code, generating patches, or fixing bugs
- When user explicitly requests a quick scan without full verification

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
| `verification-policy.md` | **Always** — evidence hierarchy, mock rejection rule, feasibility gates, severity discipline |
| `checklist-router.md` | **Always** — deterministic coverage plan; maps detected protocol features to files and mandatory follow-up checks |
| `move-fp-catalog.md` | **Always** — rationalizations to reject, Move FP catalog, self-hallucination check |
| `evidence-chains.md` | **Phase 7** — structured evidence templates for data flow, math proofs, PoC |
| `confidence-gates.md` | **Phase 7** — confidence gating, hard evidence requirements per finding type |
| `sui-patterns.md` | When chain is **Sui** (imports `sui::object`, `sui::transfer`, etc.) — SUI-01 to SUI-42 |
| `aptos-patterns.md` | When chain is **Aptos** (imports `aptos_framework`, `aptos_std`, etc.) — APT-01 to APT-25 |
| `defi-vectors.md` | When protocol involves tokens, swaps, lending, staking, or oracles — DEFI-01 to DEFI-10 + subcategory router |
| `semantic-gap-checks.md` | When the protocol has accumulators, checkpoints, rewards, lending state, cross-module accounting, or multi-step state transitions |
| `defi/defi-staking.md` | When staking/yield detected (`stake`, `unstake`, `reward_per_share`, `accumulator`) — DEFI-11 to DEFI-16 |
| `defi/defi-oracle.md` | When oracle usage detected (`get_price`, `oracle`, `pyth`, `switchboard`, `price_feed`) — DEFI-17 to DEFI-24 |
| `defi/defi-lending.md` | When lending/borrowing detected (`borrow`, `repay`, `collateral`, `health_factor`) — DEFI-25 to DEFI-34, DEFI-80, DEFI-82, DEFI-84 |
| `defi/defi-math-precision.md` | When complex financial math detected (`PRECISION`, `DECIMAL`, `float`, `Decimal`, `WAD`, fee/share math) OR when reward/accumulator/liquidity_mining patterns detected — DEFI-35 to DEFI-42, DEFI-85 to DEFI-87 |
| `defi/defi-slippage.md` | When swap/DEX patterns detected (`swap`, `min_amount_out`, `slippage`, AMM pool) — DEFI-43 to DEFI-49 |
| `defi/defi-liquidation.md` | When liquidation mechanisms detected (`liquidat`, `seize`, `bad_debt`, `insurance`) — DEFI-50 to DEFI-66, DEFI-81, DEFI-83 |
| `defi/defi-auction-clm.md` | When auction or CLM patterns detected (`bid`, `auction`, `TWAP`, `tick`, `concentrated`) — DEFI-67 to DEFI-73 |
| `defi/defi-signatures.md` | When signature verification detected (`ed25519`, `secp256k1`, `verify_signature`, `nonce`) — DEFI-74 to DEFI-79 |
| `defi/defi-lending-design-patterns.md` | When lending/borrowing detected — known-good patterns (DESIGN-L1 to L4) that should NOT be reported as bugs |
| `audit-prompts.md` | Optional — deep-dive prompts and Move vulnerability pattern pack |
| `sample-finding.md` | Reference for output format — do not load during audits |

---

## Auditor Mindset

You are a senior Move security researcher. Find real, exploitable vulnerabilities — not theoretical ones. Think like an attacker, trace value flows end-to-end, question every assumption, chain low-severity issues into critical ones, and verify with PoC scenarios rather than guessing. Consult `move-fp-catalog.md` to avoid common false positives.

---

## Workflow

### Phase 1 — Initial Assessment (auto-run on activation)

**Detect chain and framework:**
- Presence of `sui::object`, `sui::transfer`, `sui::tx_context` → **Sui Move**
- Presence of `aptos_framework`, `aptos_std`, `#[test_only]` → **Aptos Move**
- Load reference files from the skill directory (see Reference Files table above):
  - **Always** → read `common-move.md`
  - **Always** → read `verification-policy.md`
  - **Always** → read `checklist-router.md`
  - **Always** → read `move-fp-catalog.md`
  - **Sui** → also read `sui-patterns.md`
  - **Aptos** → also read `aptos-patterns.md`
  - **DeFi protocols** → also read `defi-vectors.md`, then check the subcategory detection
    table inside it and load relevant `defi/*.md` files (multiple may apply — e.g., a lending
    protocol should load `defi-lending.md`, `defi-liquidation.md`, and `defi-oracle.md`)
  - **Accumulator / checkpoint / rewards / cross-module accounting signals** (grep: `last_update`, `checkpoint`, `cumulative`, `reward_manager`, `pool_reward`, `liquidity_mining`, `accumulated`) → also read `semantic-gap-checks.md` AND `defi/defi-math-precision.md` (for DEFI-85/86/87)

**Map the codebase:**
```
- List all modules
- List all public/entry functions (these are the attack surface — see table below)
- List all structs with key/store abilities (persistent state)
- List all capability types (objects that grant permissions)
- Identify any admin/owner patterns
- Identify any cross-module calls
- Estimate complexity: LoC, number of entry points, external dependencies
```

**Coverage Plan (mandatory):**
Use `checklist-router.md` to derive a coverage plan listing: detected chain, protocol families, feature flags, reference files loaded, and required follow-up passes. If a route fires, load the file.

**Entry Point Classification:**
Attack surface differs by chain:

| Visibility | Sui (PTB-callable?) | Aptos (tx entry?) |
|------------|---------------------|-------------------|
| `public entry fun` | Yes — PTB + direct tx | Yes — transaction entry |
| `public fun` | **Yes — PTB-callable!** | **No** — module-callable only |
| `entry fun` | Yes — direct tx only | Yes — transaction only |
| `public(package) fun` | No — package-internal | No — package-internal |
| `fun` (private) | No | No |

**Critical Sui distinction:** ALL `public fun` on Sui are PTB-callable, making Sui's attack surface larger than Aptos.

**Access Control Classification — for each entry point:**
- **Sui:** Owned object with "Cap" in name → specific role; Owned object without "Cap" → Owner-gated; Shared object parameter with no cap → **Public/Unrestricted**
- **Aptos:** `signer::address_of` compared to stored address → Role-based; `exists<*Cap>(addr)` → Capability-based; `&signer` with NO address check → **Review Required** (see APT-24)
- Any function classified as Public/Unrestricted that mutates state → highest audit priority

**Build Detection & Test Log Analysis (conditional):**
Check if the project builds (`Move.toml` + `sui move build` or `aptos move compile`). If build succeeds (`BUILD_AVAILABLE = true`), run Test Log Analysis (common-move.md Section 13) to detect arithmetic aborts, assertion failures, and runtime anomalies. If build fails, note errors and skip.

**Output a one-paragraph codebase summary** (include build status) before proceeding.

---

### Phase 2 — Multi-Perspective Review

**Perspective 1 — The Attacker**
For each entry function:
- What inputs does it accept without validation?
- Can I pass an object I don't own?
- Can I bypass any `assert!` by constructing a specific state?
- Can I call this in a sequence that wasn't intended?
- (Aptos) Does any `public entry fun` accept `&signer` without ever calling `signer::address_of` for authorization? → APT-24
- (Sui) Is this a `public fun` (not just `entry`)? If so, it's PTB-composable — can it be chained with other calls to bypass per-call limits or create unexpected state?

**Perspective 2 — The Protocol Designer**
- What invariants does this protocol rely on?
- Which of those invariants are enforced on-chain vs. assumed off-chain?
- What happens if those assumptions break?

**Perspective 3 — The Integrator**
- If another protocol calls into this one, what can go wrong?
- Are there flash loan vectors?
- Can object references be reused or replayed across transactions?

**Perspective 4 — The Symmetry Checker**
For every pair of inverse operations, verify symmetry:
- deposit/withdraw: `withdraw(deposit(X)) <= X` always (rounding favors protocol)
- borrow/repay: `repay(borrow(X)) >= X` always (rounding favors protocol)
- mint/burn: `burn(mint(X)) <= X` always
- liquidation trigger/seize: same price oracle type, or bounded divergence
- rate limit add/reduce: reduce applied to same time segment as add
- admin update: only config changes, runtime state preserved
For each pair, check: (a) rounding direction, (b) state consistency, (c) oracle consistency, (d) access control symmetry

**Perspective 5 — The Consistency Checker**
When a module uses an explicit safety pattern (e.g., `EDivideByZero` guard before division, bounds check on construction params, `assert!(amount > 0)` on inputs), check if sibling modules in the same package follow the same pattern. Inconsistencies are Low.
- Grep for the pattern across all modules in the package
- If Module A guards division with an explicit zero-check but Module B performing the same operation does not → flag the inconsistency
- Also applies to: error code usage, input validation, capability checks, event emission

---

### Phase 3 — Structured Vulnerability Scan

Before starting the per-check scan, confirm the coverage plan from `checklist-router.md`
is complete. If the codebase contains a signal with no corresponding deep check loaded,
fix the plan first.

Work through every check in `common-move.md`, then the chain-specific reference. For each check:

1. Search the codebase for the pattern
2. If found: record location, describe impact, assign severity
3. If clean: note it as verified

**Do not skip checks.** A clean check is still a check — mark it ✅.

**Fixed-Point Library Inspection Gate (MANDATORY — #1 missed critical bug class):**

Before completing Phase 3, you MUST complete ALL steps and output confirmation:

1. **Identify** all math helpers: grep for `float`, `decimal`, `wad`, `ray`, `fixed_point`, `Decimal`, `WAD`, `Float`
2. **Read internals** of each helper's `mul`, `div`, `from` — do NOT assume from name
3. **Derive overflow bound** for `mul(a,b)`: write the intermediate expression, simplify to raw input constraint (e.g., `A * B <= U64_MAX`)
4. **Find all call sites** of `mul()`. For each `A.mul(B)` chain: can `A * B` exceed the bound with realistic values? (token decimals: USDC=6, SUI=9, APT=8). Compute threshold table per DEFI-85
5. **Check checkpoint ordering** for each overflow-reachable site: abort BEFORE or AFTER checkpoint? If BEFORE → Recoverability Matrix (12.1)
6. **Output:** "FIXED-POINT GATE: [N] helpers, [M] call sites, [K] overflow-reachable" — if K > 0, include threshold table + recoverability

**Skipping this gate = missing permanent-deadlock bugs.** See 2.6, 12.1, DEFI-85–87.

**Dead Code / Unreachable Branch Detection:**
Before recording any finding that depends on a specific code branch:
1. **Is the branch reachable?** Trace all callers and all paths that set the condition variable.
   If a guard like `if (!X) { continue }` exists but X is invariantly true due to
   constructor/setter validation, the entire path after the guard is dead code.
2. **TODO comments describe aspirational features, not current bugs.** A TODO saying
   "skip check for non-collateral" doesn't mean non-collateral assets exist — it means
   the developer considered adding support but didn't.
3. **Do not report findings that require executing dead code.**

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

### Phase 5 — Semantic Gap & Stale-State Scan

If the protocol has multiple accounting variables, reward indices/accumulators, checkpoints, or lending state across modules — read `semantic-gap-checks.md` and run this phase. Mandatory for lending, staking, vault, reward, liquidation, and oracle-heavy protocols.

Required outputs: writer path, stale/mismatched consumer path, persistence window, numeric trace for any High/Critical candidate.

---

### Phase 6 — Cross-Module Interaction Scan

After completing per-file analysis, explicitly trace these interaction pairs.
For each pair, ask: does function A in module X leave module Y in an
inconsistent or permanently broken state?

Required pairs to check in every lending protocol audit.

**CHECK #1 IS HIGHEST PRIORITY — do it first, do it thoroughly:**

1. **[CRITICAL PRIORITY] reward_manager_update ↔ all lending operations** —
   Does the reward/accumulator update perform arithmetic that can abort BEFORE writing
   `last_update_time`? If ALL user operations (deposit/withdraw/borrow/repay/liquidate/claim)
   AND admin recovery (cancel/close) call this update → permanent deadlock.
   (→ 12.1, DEFI-85–87). Trace: overflow bounds, checkpoint ordering, admin recovery paths, threshold table.

2. **repay ↔ rewards/liquidity_mining** —
   When repay fully clears the last debt on an obligation (permissionless path),
   is the reward tracker for that obligation cleaned up?
   If not: orphaned tracker may block pool closure. (→ common-move.md 11.1)

3. **liquidate ↔ reserve (collateral reserve)** —
   Does the liquidation path check that the collateral reserve has
   idle cash >= seize_amount before calling `balance::split()` or equivalent?
   If not: liquidation reverts at high utilization → bad debt accumulates. (→ DEFI-81)

4. **adl ↔ emode** —
   Does the ADL entry condition and the ADL stop condition both read total borrows
   from the same source (both reserve-level OR both emode-group-level)?
   If different sources → wrongful liquidation or stuck ADL state. (→ DEFI-82)

5. **admin_config ↔ interest/reserve** —
   Does every admin function that updates a rate model or fee rate call
   `accrue_interest()` before applying the new value?
   If not → retroactive rate application, mispriced interest for all users. (→ DEFI-80)

6. **liquidate ↔ close_factor** —
   Is the close factor enforced per-TRANSACTION, not per-call?
   On Sui, PTBs allow calling liquidate() N times atomically. If close factor is
   checked against current (shrinking) debt, total liquidation = 1-(1-CF)^N. (→ SUI-28, DEFI-83)

7. **admin_config ↔ rate_limiters** —
   Does the config update function preserve accumulated runtime state (limiter segments,
   accumulators, counters)?
   If config update resets limiters → sandwich attack: borrow to limit → admin resets → borrow again. (→ DEFI-84)

8. **oracle_eligibility ↔ oracle_seize** —
   Does liquidation use the same price type for both trigger and seize, OR enforce a
   bounded divergence between them?
   If borrow/withdraw enforce EMA-spot tolerance but liquidation does NOT → unbounded
   price divergence in the only operational code path during volatility. (→ DESIGN-L1 caveat)

9. **flash_loan ↔ deposit/borrow/withdraw** —
   Do operations during an active flash loan see stale accounting fields (cash, total_borrows)?
   If hot potato guarantees repayment, not updating cash is intentional (DESIGN-L2). But if
   other operations READ the stale value mid-PTB, they may misprice shares or health. (→ DESIGN-L2 caveat)

For any interaction pair where the answer is NO → report as HIGH.
This phase is mandatory. Do not skip it even if all per-file scans were clean.

---

### Phase 7 — Verify & Triage (Move-Expert Validation)

Before reporting, every candidate finding from Phases 3-6 must survive a Move-expert
verification pass. This phase eliminates false positives, corrects inflated severities,
and ensures only real, exploitable findings reach the report.

Before verifying any finding, read `verification-policy.md`, `evidence-chains.md`,
and `confidence-gates.md`. Apply:

- evidence source tagging
- the mock rejection rule
- reachability gate
- math-bounds gate
- severity discipline for High/Critical

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

**Step 2 — Move-Expert Disproof (8 Dimensions)**

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

5. **Precondition Feasibility & Invariant Reachability** — Can the attacker reach the
   vulnerable state on mainnet?
   - Sui: shared object consensus ordering — can attacker reliably front-run?
   - Aptos: Block-STM parallel execution — does execution order matter?
   - Gas costs, object creation constraints, minimum amounts, time locks
   - Does attacker need a capability/object they cannot obtain?
   - **Invariant Reachability:** If the finding requires a field to have value X, find
     EVERY code path that sets that field and verify X is achievable. Check all
     constructors, setters, and validation guards. Pay special attention to parameter
     validation in admin/init functions — they often create invariants that make edge
     cases unreachable (e.g., `assert!(a < b)` on `u64` makes `b = 0` impossible).

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

8. **Counterfactual Fix Test** — Apply your recommended fix mentally:
   - Does the fix change the **observable behavior**? If the transaction still aborts,
     the same funds are still locked, the same DoS occurs — the finding is cosmetic.
   - If downstream code would ALSO block the scenario independently of the bug,
     the bug has no incremental impact. Trace the FULL execution path PAST the
     buggy line — if the function fails at line N+5 anyway, the bug at line N
     is informational at best.
   - "Same value, different error code" is not a vulnerability — both produce
     transaction abort with identical user-facing outcome.

**Step 3 — Label Each Finding**

- **VALID** — Survives all checks. Exploitable on mainnet. Include at stated severity. Assign confidence: `confirmed` or `likely`.
- **QUESTIONABLE** — Plausible, but decisive proof is missing. Confidence: `needs_review`. Max severity: Medium.
- **DISMISSED** — Disproven by trusted local evidence (`[CODE]`, `[TEST]`, `[PROD-SOURCE]`, `[PROD-STATE]`).
- **OVERCLASSIFIED** — Real issue, severity inflated. Downgrade with reasoning. Re-assign confidence level.

**Step 4 — Mandatory Kill Questions**

Every finding labeled VALID or QUESTIONABLE must answer ALL of these. If any answer
is "no" or uncertain, downgrade or dismiss:

1. **Can I construct the precondition state through valid protocol operations?**
   Write the EXACT sequence of transactions. If you can't → INVALID.
2. **Does my recommended fix change observable behavior?**
   Apply the fix. Does the tx succeed now? Does the user get different output?
   If behavior is identical → INFORMATIONAL at best.
3. **For any function I claim "reverts when it shouldn't" — what would it DO if it
   didn't revert?** Would the result be meaningful? (e.g., ADL on zero-collateral:
   even without revert, seized=0, repaid=0 → no-op.)
4. **Is this a pattern used by established protocols (Compound, Aave, MakerDAO)?**
   If yes, load `defi/defi-lending-design-patterns.md` and check whether this is a
   known-good design. Explain why THIS protocol's context differs if reporting.
5. **Who loses money, how much, and under what conditions?**
   If you can't name a specific dollar impact and a specific victim → downgrade severity.
6. **Am I hallucinating this vulnerability?** Re-read the ACTUAL source code now.
   Does the code I'm referencing exist? Can I name exact file:line? Run the
   Self-Hallucination Check in `move-fp-catalog.md` Section 3. If any check fails → INVALID.

**Step 5 — Root-Cause Deduplication**

Before finalizing the finding list, group by the single LINE OF CODE that would
need to change, not by downstream effect:
- "Division by zero when X is zero" and "Function reverts when X is zero" → SAME finding
- "EMA/spot asymmetry" reported as tolerance bypass vs withdrawal blocking → SAME finding
- "Cash not updated" reported as exchange rate issue vs liquidity check issue → SAME finding

Keep only the highest-impact framing of each root cause.

**Evidence Audit (mandatory):** For every non-trivial finding, include a short evidence
table from `verification-policy.md` showing each decisive claim and its source tag.

**Output rules:** Only VALID and QUESTIONABLE findings proceed to Phase 8.
DISMISSED findings go to "Verified Clean Checks" with dismissal reason.
OVERCLASSIFIED findings proceed at adjusted severity.

---

### Phase 8 — Report

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
| Confidence | VALID (`confirmed`/`likely`) / QUESTIONABLE (`needs_review`) |
| Location   | module_name.move, line N, function name |
| Category   | [Access Control / Arithmetic / Resource Safety / etc.] |

**Description:**
Clear explanation of what the vulnerability is and why it exists.

**Attack Scenario (PoC):**
Step-by-step exploitation using Move-specific primitives with concrete values.

**Verification:** Disproof dimensions challenged and passed.

**Recommended Fix:**
Concrete code-level recommendation. Show the fix, not just the concept.

---
```

After all findings, add `## Verified Clean Checks` (with DISMISSED findings and reasoning) and `## Auditor Notes` (code quality, centralization, upgrade risks).

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

**Admin-origin latent user DoS:** Never dismiss a bug as "admin-only" or "trusted setup" if the admin action is routine (e.g., adding a reward program, setting a fee rate) and unprivileged users or liquidators are later bricked. Severity is based on who is blocked and what is blocked (fund lock, liquidation failure), not on who created the initial configuration. See common-move.md 12.2.

---

## Important Rules

- **Never hallucinate findings.** If you cannot point to exact code that is vulnerable, do not file a finding.
- **Always cite exact file + line + function.** No vague references.
- **Provide a PoC scenario for every High and Critical.** If you can't construct one, downgrade severity.
- **AI output is not final.** Always flag that findings must be manually verified and tested before reporting.
- **One contract at a time.** If given a multi-module codebase, audit module by module and flag cross-module interactions separately.
