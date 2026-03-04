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
