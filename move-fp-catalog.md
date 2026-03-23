# Move False Positive Catalog

Load this file on **every audit**. It prevents the most common LLM false positives
when auditing Move smart contracts on Sui and Aptos.

---

## Section 1: Rationalizations to Reject

When you catch yourself thinking one of these, STOP and apply the correction.

| # | LLM Shortcut (what you're tempted to say) | Why it's wrong in Move | Required action before reporting |
|---|-------------------------------------------|------------------------|----------------------------------|
| 1 | "No access control on this function" | Sui object ownership IS access control — if the function takes `&mut MyObject` (owned), only the owner can call it | Check whether params are owned objects; if yes, ownership is the gate |
| 2 | "Unchecked arithmetic — overflow possible" | Move aborts on overflow (DoS, not silent corruption). DoS is only a finding if attacker profits from the abort | Prove the attacker profits from the abort or that the abort permanently bricks state. **CRITICAL WARNING: Do NOT dismiss overflow in accumulator/reward/interest update functions without checking the abort-before-checkpoint pattern (12.1, DEFI-85/86). If the overflow occurs BEFORE `last_update_time` is written, it causes PERMANENT deadlock — this is the #1 missed High/Critical in Move audits.** |
| 3 | "Missing signer check" | On Sui, the function may only be callable via PTB with owned objects — the signer is implicit. On Aptos, check whether upstream callers validate `signer::address_of` | Trace ALL callers and check if an upstream gate already validates the signer |
| 4 | "This pattern looks dangerous" | Pattern recognition is not analysis. Move's type system eliminates many patterns that are dangerous in other languages | Complete a full data flow trace before claiming the pattern is exploitable |
| 5 | "Similar code was vulnerable in Solidity" | Move has no reentrancy (no dynamic dispatch), no delegatecall, no fallback functions, no storage collisions. The Solidity mental model does not transfer | Verify this specific Move instance is exploitable using Move-specific primitives |
| 6 | "The function is public so anyone can call it" | On Aptos, `public fun` is NOT a transaction entry point — only `public entry fun` and `entry fun` are. On Sui, `public fun` IS PTB-callable | Check the chain. On Aptos, verify `entry` keyword. On Sui, confirm PTB composability risk |
| 7 | "No input validation on amount parameter" | The upstream caller may construct the value from a safe source (e.g., `coin::value()`, a stored field). Not all inputs come from users | Trace the ACTUAL callers and the source of the value before claiming it's unvalidated |
| 8 | "I'll explain the exploit verbally" | If you can't write an exact PTB/transaction sequence, you're probably hallucinating the exploit. No artifact = no finding | Write the exact PTB sequence (Sui) or transaction script (Aptos) showing the exploit |
| 9 | "This is clearly critical severity" | LLMs systematically overrate severity. Our benchmark shows 25% false positive rate, mostly from inflated severity | Prove with concrete evidence: who loses money, how much, under what conditions |
| 10 | "Rapid analysis of remaining checks — all clean" | Every check gets full verification. Rushing the tail produces false negatives AND false positives | Verify each check through all steps. No batch dismissals |

---

## Section 2: Move-Specific False Positive Patterns

These patterns APPEAR vulnerable but are protected by Move's design. Do NOT report
them unless you have concrete evidence of ACTUAL harm despite the protection.

### 2A. Sui Object Model FPs

| # | Pattern that looks vulnerable | Why it's safe | When it IS a real bug |
|---|------------------------------|---------------|----------------------|
| 1 | Function takes `&mut T` with no explicit auth check | Owned objects: only the owner can pass them to a PTB. The object parameter IS the access control | When the object is `shared` — then anyone can pass it. Check `share_object` calls |
| 2 | Object created with `object::new(ctx)` — no uniqueness check | `UID` is globally unique, generated from transaction digest + creation count. Collision is cryptographically impossible | Never — this is always safe |
| 3 | Admin function has no signer check | If the function requires an `AdminCap` (owned object), only the cap holder can call it. Cap IS the signer equivalent | When the `AdminCap` has `store` ability and can be transferred to an attacker, or when it's a shared object |
| 4 | Token can be spent twice (double-spend claim) | Linear types: `Coin<T>` has no `copy`, so it cannot be duplicated. Spending consumes it | Never in standard Move — only if someone wraps a value in a struct with `copy` ability |
| 5 | Object ID collision between different types | Sui objects are typed — `Pool<SUI>` and `Pool<USDC>` cannot collide even with same ID (which is impossible anyway) | Never — this is always safe |
| 6 | `transfer::transfer` called without ownership check | `transfer::transfer` for owned objects already requires the caller to possess the object (linear type) | When using `transfer::public_transfer` on a shared object without validating the recipient |
| 7 | Wrapped object can be accessed by attacker | Wrapped objects (inside another struct) are inaccessible until unwrapped by the parent's module | When the parent module exposes an `unwrap` function without proper authorization |
| 8 | Shared object concurrent access race condition | Sui's Narwhal/Bullshark consensus serializes all accesses to a shared object within an epoch. No TOCTOU within a transaction | When the protocol relies on cross-transaction ordering (e.g., "first come first served" without explicit sequencing) |

### 2B. Move Type System FPs

| # | Pattern that looks vulnerable | Why it's safe | When it IS a real bug |
|---|------------------------------|---------------|----------------------|
| 1 | Generic function `<T>` accepts any type | Move generics are monomorphized at compile time. The type must satisfy ability constraints | When the function doesn't check `T` against a whitelist and `T` controls pricing/collateral value |
| 2 | Capability can be forged by attacker | If capability struct has only `key` (no `copy`, no `store`), it cannot be duplicated or transferred outside the module | When capability has `copy` or `store` ability — check the struct definition |
| 3 | Reentrancy via external module call | Move has no dynamic dispatch, no callbacks, no fallback functions. All calls are statically resolved | Never in standard Move — cross-module calls are deterministic. But check for state inconsistency between pre-call and post-call |
| 4 | Hot potato not enforced (flash loan repayment) | Hot potato structs (no `drop`, no `store`, no `copy`, no `key`) MUST be consumed in the same transaction. Compiler enforces this | Never — compiler guarantee. But verify the struct actually lacks all four abilities |
| 5 | Phantom type parameter creates confusion | `phantom` type parameters have no runtime effect — they're compile-time markers only | Never — they cannot affect runtime behavior |
| 6 | Function constraint bypass | Ability constraints on generics (`T: store + drop`) are compiler-enforced, not runtime-checked | Never — compiler guarantee. But verify constraints are present and correct |

### 2C. Move Abort Semantics FPs

| # | Pattern that looks vulnerable | Why it's safe | When it IS a real bug |
|---|------------------------------|---------------|----------------------|
| 1 | Arithmetic overflow in financial calculation | Move aborts on overflow — state is NOT corrupted. The transaction simply fails | When the abort permanently bricks state (abort-before-checkpoint pattern — see DEFI-85/86) or when attacker profits from the DoS. **BEFORE dismissing ANY arithmetic overflow, you MUST check: (1) Is this inside a periodic update function? (2) Is the state checkpoint written AFTER the overflow point? (3) Does the time delta grow on retry? If all three YES → PERMANENT DEADLOCK, not a false positive.** |
| 2 | Subtraction underflow on balance check | Abort prevents negative balances — this IS the protection, not the bug | When the abort prevents a legitimate user action (e.g., repayment, liquidation) that should succeed |
| 3 | `assert!` failure aborts the transaction | The abort prevents the invalid state from being written. The revert IS the protection | When the assert condition is wrong (too strict or too lenient) — check the condition logic, not the abort |
| 4 | Division by zero aborts | Abort prevents undefined behavior. State remains consistent | When zero divisor is reachable in normal operation and blocks legitimate actions |
| 5 | Multiple operations abort on same condition | "Same value, different error code" is not a vulnerability. Both produce transaction abort with identical user outcome | Never — if the outcome is identical abort, there's no incremental impact |

### 2D. PTB/Transaction Composition FPs

| # | Pattern that looks vulnerable | Why it's safe | When it IS a real bug |
|---|------------------------------|---------------|----------------------|
| 1 | Sandwich attack on Sui | Sui has no public mempool — validators batch transactions. Sandwich requires validator collusion | When the finding accounts for validator-level adversary and the economic incentive justifies it |
| 2 | Close factor bypassed by calling liquidate() twice | If close factor is enforced per-TRANSACTION (checking cumulative liquidation), repeated calls don't help | When close factor is checked per-CALL against current (shrinking) debt — then PTB repetition bypasses it (SUI-28) |
| 3 | PTB reordering attack | PTB commands execute in deterministic order as specified by the sender. There's no reordering within a PTB | Never within a single PTB — but cross-PTB ordering depends on consensus |
| 4 | Flash loan repayment bypass | Hot potato pattern (no `drop` ability) makes non-repayment a compiler error, not a runtime check | Never if hot potato is correctly implemented (verify abilities) |
| 5 | Front-running shared object access | Narwhal/Bullshark consensus serializes shared object access. Ordering is not first-come-first-served | When the protocol's correctness depends on transaction ordering within an epoch (e.g., auction end times) |

### 2E. DeFi Design Pattern FPs

| # | Pattern that looks vulnerable | Why it's safe | When it IS a real bug |
|---|------------------------------|---------------|----------------------|
| 1 | Flash loan not updating accounting fields (cash, debt) | Hot potato guarantees same-tx repayment. Decrementing cash would understate reserves during the loan window (DESIGN-L2) | When other operations READ the stale value mid-PTB and misprice shares or health |
| 2 | EMA for liquidation eligibility, Spot for seize | Liquidator sells collateral at spot price. Using EMA for seize makes liquidation unprofitable during rapid price drops (DESIGN-L1) | When there's no bounded divergence check between EMA and spot in the liquidation path |
| 3 | Blocking borrows when idle cash < reserve | Protective — ensures protocol fees are not lent out. Resolves as loans are repaid (DESIGN-L3) | When the blocking also prevents repayment or liquidation (not just new borrows) |
| 4 | Liquidation skipping rate limiters | Liquidations must proceed regardless to maintain solvency | When the skip also bypasses other critical safety checks (not just rate limits) |
| 5 | Interest rate returning 0 at low utilization | Expected from fixed-point truncation at near-zero rates | When it enables economically significant free borrowing over meaningful time periods |
| 6 | Liquidation bonus matching industry standard (5-10%) | Standard incentive range used by Compound, Aave, MakerDAO | When the bonus exceeds collateral margin or creates profitable self-liquidation |
| 7 | Interest rate kink/jump model behavior | Steep rate increase above optimal utilization is intentional — it incentivizes repayment | When the kink parameters create discontinuities that can be gamed |
| 8 | Admin parameter setting as sole finding | Admin actions are trusted unless admin is untrusted by design | When admin action is routine AND unprivileged users are later bricked (see common-move.md 12.2) |

### 2F. Documented Design Constraints Are Not Medium+ Findings

| # | Pattern that looks vulnerable | Why it's safe | When it IS a real bug |
|---|------------------------------|---------------|----------------------|
| 1 | Code behavior has explicit security warnings in code comments | The code is working as designed and documented — the developer already considered and accepted this trade-off | When there is NO structural mitigation and the footgun is easy to trigger unintentionally |
| 2 | Wrapper lacks `store` ability (prevents shared-object embedding) | Structural mitigation at the type level — integrators cannot misuse it even if they ignore docs | Never — if the type system prevents the misuse, documenting it is defense-in-depth |
| 3 | Multiple inline warnings (e.g., 3+ comments) about a known limitation | Developer has explicitly warned integrators; triggering requires intentionally ignoring documentation | When the docs warn but the API makes the dangerous path the easiest/default one |

**Rule:** If a behavior is:
1. Documented with explicit security warnings in code comments (not just README), AND
2. Has structural mitigations (e.g., no `store` ability, no public constructor for dangerous state), AND
3. Requires the integrator to intentionally ignore documentation to trigger

Then the maximum severity is **Informational**. The code is working as designed and documented.

**Counter-example:** If the documentation warns but there is NO structural mitigation and the footgun is easy to trigger, Low may be appropriate.

---

## Section 3: Self-Hallucination Check Protocol

**Mandatory:** Run this checklist after concluding each finding. Re-read the actual
source code AFTER reaching your conclusion — not before.

### 5-Point Checklist

For every finding you're about to report, answer ALL five questions:

1. **Can I name the exact file and line number?**
   - If you can only vaguely point to "somewhere in the lending module" → STOP.
   - Re-read the file and find the exact line.

2. **Can I write the exploit PTB/transaction sequence?**
   - Write it out now: `1. MoveCall(pkg::mod::fn(args))`, `2. ...`
   - If you can't write concrete steps → the exploit is probably hallucinated.

3. **Does the code I'm referencing ACTUALLY exist?**
   - Re-read the source file RIGHT NOW.
   - Check: Is the function name correct? Does it have the signature I think?
   - Check: Does the line I'm citing contain what I think it contains?
   - LLMs frequently confuse function names, parameter orders, and line numbers.

4. **Did I re-read the code AFTER reaching my conclusion?**
   - Confirmation bias: once you decide something is a bug, you see evidence
     that confirms it and ignore evidence that refutes it.
   - Re-read the function, its callers, and its callees NOW. Look for:
     - Assert conditions you missed
     - Upstream validation you didn't trace
     - Downstream checks that make the bug unreachable

5. **Am I pattern-matching on scary-looking code?**
   - "This looks like the Solidity reentrancy pattern" → Move has no callbacks
   - "This looks like an unchecked return" → Move forces handling via types
   - "This looks like an access control issue" → Check owned objects first
   - If your reasoning is "it looks like X" rather than "the data flows from A
     through B to C causing D" → your analysis is incomplete.

### Failure Protocol

If ANY of the 5 checks fails:
- Do NOT include the finding in the report
- Go back to the source code and redo the analysis from scratch
- If the finding still fails after re-analysis → mark as DISMISSED with reason
  "failed self-hallucination check #N"
