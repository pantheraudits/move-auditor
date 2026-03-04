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
