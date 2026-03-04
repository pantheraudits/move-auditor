# Move Audit Prompts & Vulnerability Pattern Pack

Supplementary prompts for deep-dive manual review. Load this file when you want
targeted prompts for specific modules, functions, or resources.

---

## Generic Move Audit Prompts (Adapted Checklist)

Use these prompts directly during manual review or with an AI assistant. Replace
`<module>`, `<function>`, and `<resource>` with concrete code targets.

### A. Attack Surface & Privileges

- "List every `public` and `entry` function in `<module>`. For each, state who is allowed to call it and how that is enforced on-chain."
- "Find every code path that can mutate protocol-critical state in `<module>`. Highlight any path that lacks signer or capability authorization."
- "Identify all capability-like structs in `<module>`. Explain whether any ability set (`copy`, `store`, `drop`) makes privilege escalation possible."
- "Trace admin authority from initialization to current state. Can admin rights be lost, duplicated, or unintentionally transferred?"

### B. Asset & Value Flow

- "Trace all asset inflows/outflows in `<module>` and confirm accounting invariants hold after each state transition."
- "For each user credit/mint operation, show the exact on-chain asset movement that backs it. Flag any synthetic or unbacked credit path."
- "Check whether any withdraw/redeem path allows receiving more value than deposited due to rounding, ordering, or stale state."
- "Identify whether the protocol can become insolvent if edge-case aborts happen mid-flow."

### C. Arithmetic & Precision

- "Review all arithmetic in `<function>`. Show where caller-controlled inputs can force aborts (underflow, overflow, divide-by-zero)."
- "Find all formulas using division. Verify multiplication-before-division where precision matters."
- "Identify all casts to smaller integer types and verify explicit bounds checks before narrowing."
- "Evaluate whether rounding direction (up/down) consistently favors protocol safety."

### D. Resource & Storage Safety

- "Review every `move_from`, `borrow_global`, and `borrow_global_mut` use in `<module>`. Verify ownership or capability checks are enforced first."
- "Identify any storage read/write that can abort via missing resource/key and assess whether this can be used for DoS."
- "Map lifecycle of each `<resource>`: creation, storage, mutation, and destruction. Flag orphaned or unreachable states."
- "Check whether resource extraction, table removal, or object transfer can occur for addresses not controlled by caller."

### E. State Machines & Invariants

- "Document the intended state machine for `<module>`, then list all valid transitions and where each is enforced."
- "Find transitions that can be skipped, repeated, or executed out of order."
- "List core invariants (supply, collateralization, ownership, one-time init) and show where each invariant is asserted."
- "Review boundary checks (`>`, `>=`, `<`, `<=`) and identify off-by-one conditions that unlock restricted actions."

### F. External Dependencies & Integrations

- "List all cross-module calls from `<module>` and explain assumptions made about return values and side effects."
- "Check whether protocol state is left inconsistent before external calls and whether failures can strand partial updates."
- "Identify dependencies on upgradeable external modules and describe how an upgrade could violate local assumptions."
- "For oracle/pricing dependencies, verify stale, missing, or manipulated data cannot create profitable attack paths."

### G. Initialization, Upgrades, Emergency Controls

- "Audit `init`/`initialize` logic: prove it is one-time-only and cannot be replayed through alternate entry points."
- "Identify all upgrade authorities and classify operational risk (single key, multisig, timelock, immutable)."
- "Check if emergency pause/kill-switch exists, who controls it, and whether it can be abused for censorship or fund lock."
- "Review migration/upgrade flows for storage compatibility and privilege continuity."

### H. Adversarial Scenario Prompts

- "Assume attacker has zero privileges and arbitrary call sequencing. What is the shortest path to unauthorized fund movement?"
- "Assume attacker can create many accounts and send dust inputs. Can they trigger systemic aborts or gas-based DoS?"
- "Assume attacker can exploit timing/epoch boundaries. Which functions become exploitable at boundary conditions?"
- "Assume a privileged key is compromised. What is maximum blast radius and time-to-mitigation?"

---

## Move Vulnerability Patterns Prompt Pack (from web3-sec-ai-prompts)

Source: `common/move-patterns.md` in Panther Audits `web3-sec-ai-prompts`.

### Purpose

Use this prompt to check a Move contract against the most common vulnerability
patterns found across 200+ public Move audit reports (1141 findings). Covers
Sui, Aptos, Supra, and other Move-based chains.

Reference database: [Move Vulnerability Database](https://movemaverick.github.io/move-vulnerability-database/)

### Master Prompt

```text
You are a Move smart contract security expert. Review the following contract and check for these vulnerability patterns, derived from 1141 real findings across 200+ audited Move protocols.

[Paste contract code or reference file path]

The top 5 vulnerability classes account for 70%+ of all Critical/High findings in Move. Check them first.

1. Business Logic (296 findings, 21 Critical, 58 High)
- Reward/staking timing exploits
- Flash loan reward manipulation
- Liquidation logic flaws
- Partial close/withdrawal bypasses
- Pool creation validation
- Constant product invariant breaks
- State reset on update
- Queue/tree data structure bugs

2. Input Validation (170 findings, 16 Critical, 29 High)
- Missing generic type checks
- Missing UID/object validation
- Flash loan receipt manipulation
- Zero-value inputs
- Arbitrary asset repayment
- Signature validation
- Uncallable functions

3. Calculation Errors (148 findings, 13 Critical, 28 High)
- Precision/decimal mismatches
- Scaled vs unscaled mixing
- Time constant errors
- Double scaling
- Share price manipulation
- Arithmetic overflow
- Formula errors
- Missing rewarder updates
- Refund precision

4. Access Control (73 findings, 13 Critical, 20 High)
- Public function visibility (`public` vs `public(package)`/`public(friend)`)
- Missing capability checks
- Resource signer exposure
- Liquidation access control inconsistencies
- Test code in production
- Pool creation permissions
- Front-running via public minting

5. State Management (64 findings, 7 Critical, 14 High)
- Stale state dependencies
- Incorrect index tracking
- Tail pointer corruption
- Accumulator ordering
- Timestamp manipulation
- Recording zero values

6. Oracle Issues (27 findings, 3 Critical, 5 High)
- Stale price acceptance
- Price manipulation via low-liquidity sources
- Incorrect decimal scaling
- Missing circuit breaker / deviation bounds

7. Denial of Service (40 findings, 2 Critical, 4 High)
- Unbounded loops over dynamic collections
- Single bad entry blocking batch operations
- Arithmetic overflow causing function-level DoS

8. Data Inconsistency (31 findings, 2 Critical, 10 High)
- Non-atomic state updates across related variables
- Incorrect/stale event emission
- Cross-module state assumption drift

9. Constant Definition (21 findings, 3 Critical, 2 High)
- Wrong constant values
- Constants not matching specs/docs
- Hardcoded values that should be configurable

10. Front-Running (7 findings, 0 Critical, 3 High)
- Ordering manipulation
- Payload front-running
- Missing commit-reveal for sensitive flows

For each pattern found:
1. State the specific vulnerability class from the list above
2. Indicate severity (Critical/High/Medium/Low) with justification
3. Point to the exact code location
4. Describe the exploit scenario
5. Reference similar historical findings from Move audits if applicable
```

### High-Signal Usage Tips

- Prioritize top 3 classes first: business logic, input validation, and calculation errors.
- Always audit generic type parameter validation in every function that accepts generic types.
- Treat Move function visibility as a first-class access-control surface: review every `public` function.
- Use this with the verification checklist in `common-move.md` for broad + Move-specific coverage.

---

## MVD-Derived Targeted Prompts

These prompts target the most frequently exploited patterns from 200+ real Move audit reports.
Use them for focused deep-dives after the initial scan.

### I. Generic Type & Receipt Validation

- "Find every function with a generic type parameter `<T>`, `<CoinType>`, `<X, Y>`, etc. For each, trace how the type is validated. Flag any function where the type parameter is not bound to the pool, vault, or receipt it operates on — an attacker can pass any coin type."
- "Find all flash loan / flash swap functions. Trace the receipt from creation to repayment. Is the receipt's pool ID / coin type validated during repayment? Can a receipt from Pool A be repaid to Pool B?"
- "Search for functions that accept an object reference (`&T`, `&mut T`) used for pricing, share calculation, or permission checks. Is the object's ID validated against a registry or known constant? Could an attacker create their own instance with manipulated values?"

### J. Constant & Scaling Verification

- "Grep all `const` definitions in the codebase. For each constant: (a) verify the value matches its name (e.g., `DAY_SECONDS` should be 86400), (b) check MAX_U64/MAX_U128 have the correct number of digits, (c) verify time constants (seconds vs milliseconds) are consistent with how they're used. Flag any mismatch — these are Critical/High bugs."
- "Find all variables named `scaled_*`, `index_*`, or `*_per_share`. Trace every arithmetic operation that uses them. Are they ever mixed with raw token amounts without conversion? Are there places where a scaled value is compared to an unscaled value or vice versa?"

### K. State Update & Repeated Action Prevention

- "For every function that transfers tokens, mints shares, or distributes rewards: does it update state to prevent being called again for the same entitlement? Search for claim/refund/withdraw functions that don't set a `claimed` flag, don't burn the receipt, or don't decrement the claimable balance."
- "Find every fee collection point (`balance::join`, `coin::put`, `coin::merge_all`). For each, trace if there's a corresponding admin withdrawal function. If fees accumulate with no extraction path, they're permanently locked."

### L. Accumulator & Reward Manipulation

- "Identify all reward accumulator / `reward_per_token` / `reward_per_share` update logic. Can an attacker stake a large amount, trigger an accumulator update, then immediately unstake and claim inflated rewards — all in one transaction? Is there a minimum staking duration enforced?"
- "For every stake/unstake function pair: simulate a flash loan attack where an attacker borrows → stakes → claims → unstakes → repays in one transaction. What is the maximum extractable value? Is this prevented by time-based locks or snapshot-based calculations?"

### M. Liquidation & Solvency

- "Trace the complete liquidation flow from health check to collateral seizure. At each step, verify: (a) the correct variable is passed (debt amount vs collateral amount), (b) solvency is checked AFTER withdrawal/repayment, (c) liquidation cannot be blocked by cooldowns or paused states, (d) remaining collateral is returned to the user, not destroyed."
- "For every `withdraw` function in a lending protocol: is there a solvency check AFTER the withdrawal amount is deducted? Can a user withdraw collateral while their position is underwater?"

---

## Audit Methodology — Rules & Heuristics

Core audit rules and thinking heuristics. Apply these throughout every review
alongside the pattern-specific checks above.

### 1. Trust Model

- **Admin is trusted** — check the specs/docs for which roles are trusted.
  Don't report findings based on trusted actors acting maliciously. However,
  **logic bugs in admin actions are valid findings** — if an admin function
  has a code bug that causes unintended behavior, that's reportable.
- **Defense in Depth:** Assume any privileged account can be compromised.
  Evaluate blast radius — can a compromised admin rug the entire protocol?
  Can they drain all funds in one transaction, or are there timelocks/limits?
- **Principle of Least Privilege:** No actor should have more power than needed.
  If a value can be read on-chain, a function shouldn't accept it as an
  arbitrary parameter. If a function only needs read access, it shouldn't
  take `&mut`.

### 2. Asymmetry Detection

This is one of the highest-signal audit techniques. Open similar functions
side by side and compare line by line.

**Compare these pairs:**
- `deposit` vs `withdraw`
- `buy` vs `sell`
- `mint` vs `burn`
- `borrow` vs `repay`
- `stake` vs `unstake`
- User version vs admin version of the same action (e.g., user redemption vs force redemption)

**What to look for:**
- A check present in one function but missing in its counterpart
- One function uses an oracle/on-chain value; its counterpart accepts an arbitrary parameter
- Different rounding directions that should be symmetric (or asymmetric for protocol safety)
- Admin functions are underrepresented in testing and frequently contain critical bugs —
  devs focus on user flows and neglect admin flows

**Bad symmetry (defensive code as a vulnerability):**
A safety check duplicated from a "prepare" function into a "redeem/claim" function
can cause permanent DoS if the prepare step already decremented the counter to zero.
Too-restrictive checks can brick functionality — defensive code can itself be a
critical vulnerability.

### 3. State Variable Deep Dive

- **Enumerate all state variables** (struct fields in `key` resources, shared objects,
  table entries). For each one:
  - Where is it written? Is it updated correctly at every mutation point?
  - Can an attacker manipulate it to reach an exploitable state?
  - Is it ever read after a mutation in the same function without refresh?
- **Setter/update functions:** When a setter changes a state variable, does it
  retroactively impact any live instance? E.g., changing a fee rate mid-epoch
  that affects already-accrued rewards, or updating an address without
  reclaiming tokens/allowances from the old one.
- **Coding pattern present everywhere except one place:** If a state update
  pattern (e.g., `update_rewards()` before balance change) appears in 9 out
  of 10 functions, the missing 10th instance is likely a bug.

### 4. Constants & Formulas

- For every `const` defined in the contract: check if it's defined correctly,
  check its usage in the code. Is it logically correct? Is it technically
  implemented correctly? The formulas and math where it's used — are they
  correct or do they have bugs?
- **Copy-paste errors:** When you see similar constants, hashes, or IDs,
  verify they're actually different. Search for duplicate values across the
  codebase with grep.
- See `common-move.md` section 8.4 for specific constant bugs from real audits.

### 5. Input Validation & Edge Cases

- **Check for these edge-case inputs on every public/entry function:**
  - Zero values (`amount = 0`) — does it corrupt state, skip logic, or divide-by-zero downstream?
  - Very small values (1 unit) — dust attacks, rounding exploits
  - Very large values (near MAX_U64) — overflow in multiplication
  - Empty vectors/lists — loop bypass: if a `while` loop iterates over a user-supplied
    vector and returns a result, what happens with an empty vector? The loop is skipped
    and may return a default value (e.g., `true`) that bypasses validation.
  - Identical inputs (same address for sender and recipient, same coin for both sides of a swap)
  - Unvalidated object/address references — can a user pass a malicious object that
    implements the expected struct layout?
- **Do functions validate that token/coin types actually belong to the protocol?**
  Can a user pass in a worthless self-created coin type?
- **Many small ops vs one large op:** Do many small deposits/withdrawals produce
  the same end state as one large one? If not, there's a bug (rounding, fees,
  state corruption). This is a powerful black-box testing technique.

### 6. Arithmetic & Precision

- **Casting bugs:** Casting a `u128` to `u64` truncates silently. Multiplying
  two `u64` values and storing in `u64` overflows even if the result is assigned
  to a `u128` later — must cast *before* multiplying.
- **Precision annotation technique:** For each variable in a formula, annotate
  its decimal precision (e.g., `// 6 decimals`, `// 18 decimals`, `// RAY = 27`).
  Look for addition/subtraction between variables of different precision.
  Common pattern: protocol uses internal precision (e.g., 18 decimals) but
  interacts with tokens of different precision (e.g., USDC 6 decimals) —
  look for missing or incorrect conversion.
- **Off-by-one errors:** `<` vs `<=`, especially with slightly different checks
  in different functions. Compare boundary conditions across all functions that
  reference the same threshold.

### 7. Look for What's Missing

**Missing checks are harder to spot than incorrect ones.** Train yourself to
notice absence:

- Missing access control on a privileged function
- Missing solvency check after withdrawal
- Missing existence check before table access
- Missing state update after claim/refund
- Missing fee withdrawal function (locked funds)
- Missing pause mechanism (no emergency brake)
- Missing minimum amount check (enables dust/1-wei attacks — recommend protocols
  implement minimums to cut off these vectors)
- Missing duplicate check when adding to a list (duplicates can break downstream logic)
- Missing slippage protection on any function that interacts with AMM pools
  (especially admin functions like unpause, setPositionWidth, rebalance)
- Missing reclamation when updating an address (if a function updates an external
  contract address, does it first reclaim tokens from the old address?)
- Missing decimal adjustment when changing a token address (if a function allows
  changing a token, does the new token have different decimals? Will that corrupt
  internal accounting?)

### 8. Unchecked Return Values

- Functions that return `bool` instead of aborting on failure — do callers check
  the return value? In Move, most operations abort on failure, but custom functions
  may return `bool` or `Option` to indicate success/failure.
- Check all cross-module calls: is the return value validated before being used
  in critical logic?
- Especially dangerous: functions that return `(bool, u64)` where the caller
  uses the `u64` without checking the `bool`.

### 9. Black-Box Testing Mindset

- Code up scenarios with known expected inputs, outputs, and state changes.
  Run them mentally (or write test cases) and see if actual results match.
  Reverse-engineer the bug location from unexpected outputs.
- **Gaps in test suite:** Look for untested interactions between modules,
  edge cases not covered, and paths that are only tested with happy-case inputs.
- **Use the protocol as an attacker would:** Try to construct a sequence of
  transactions that reaches an invalid state. Think in PTBs (Sui) or
  multi-step transactions (Aptos).

### 10. Beyond the Checklist

The rules above cover known patterns. But the highest-value findings often come
from areas NOT on any checklist. Use your experience and imagination:

- **Explore all possible paths** — check every single line and all flows
- **Question every assumption** the developer made
- **Think about what the code does, not what it's supposed to do**
- **Read the code as if you've never seen it before** — fresh eyes catch
  what familiarity blinds you to
