# Evidence Chains

Load this file during **Phase 7 — Verify & Triage**. It provides structured evidence
templates for proving or disproving Move audit findings.

Every non-trivial finding must include at least one completed evidence template.

---

## Section 1: Data Flow Evidence Template

Trace data from source to sink. Every step must cite exact code.

```
### Data Flow: [finding title]

| Step | Location | Description | Trust Level |
|------|----------|-------------|-------------|
| Source | `file.move:NN` | Where the value originates | [see levels below] |
| Validation | `file.move:NN` | What checks the value passes through | — |
| Transform | `file.move:NN` | How the value is modified | — |
| Sink | `file.move:NN` | Where the value is consumed / stored | — |

**Attacker-controlled?** Yes / No — because [reason]
**Validation gap?** Yes / No — because [reason]
```

### Move Trust Levels

| Source | Trust Level | Rationale |
|--------|------------|-----------|
| Owned object parameter | Owner-trusted | Only the object owner can pass it in a PTB/tx |
| `&signer` (Aptos) | Signer-trusted | Transaction signer verified by runtime |
| Shared object parameter | **Untrusted** | Anyone can reference a shared object |
| `Cap`-gated parameter | Capability-holder-trusted | Only the cap holder can call |
| `clock::timestamp_ms` / `TxContext` | System-trusted | Provided by validators, not user-controllable |
| Function argument (non-object) | **Untrusted** | Caller can pass arbitrary values |
| `dynamic_field::borrow` result | Context-dependent | Trusted if parent object is owned; untrusted if shared |
| Return value from external module | **Untrusted** | Unless verified from source (tag `[PROD-SOURCE]`) |

---

## Section 2: Mathematical Bounds Proof Template

For any finding involving arithmetic overflow, precision loss, or economic thresholds.

```
### Math Proof: [finding title]

**Expression:** [the exact arithmetic expression from code, e.g., `a * b / c`]
**Location:** `file.move:NN`

**Variable bounds:**
| Variable | Type | Min | Max | Source of bound |
|----------|------|-----|-----|-----------------|
| a | u64 | 0 | 18_446_744_073_709_551_615 | type max |
| b | u64 | 0 | [realistic max from protocol] | `file.move:NN` |
| c | u64 | 1 | [realistic max] | assert at `file.move:NN` |

**Overflow check:**
- Intermediate: `a * b` max = [value] → overflows u64? Yes/No
- With realistic values: `a * b` max = [value] → overflows? Yes/No
- Trigger condition: [exact values that cause overflow]

**Precision loss check:**
- `a / c` when a < c → result = 0? Impact: [describe]
- Rounding direction: floor (favors protocol / favors user?)

**Conclusion:** Overflow/precision loss IS/IS NOT reachable with production values.
```

### Move Integer Type Reference

| Type | Bits | Max Value |
|------|------|-----------|
| u8 | 8 | 255 |
| u16 | 16 | 65,535 |
| u32 | 32 | 4,294,967,295 |
| u64 | 64 | 18,446,744,073,709,551,615 (~1.8×10¹⁹) |
| u128 | 128 | ~3.4×10³⁸ |
| u256 | 256 | ~1.15×10⁷⁷ |

---

## Section 3: Attacker Control Analysis Template

Enumerate what the attacker controls and how they exercise that control.

```
### Attacker Control: [finding title]

**Chain:** Sui / Aptos

**Control surfaces:**
| Control Type | What attacker controls | How | Constraints |
|-------------|----------------------|-----|-------------|
| PTB composition (Sui) | Call sequence, arguments | Constructs PTB with MoveCall commands | Must use `public` or `entry` functions only |
| Transaction script (Aptos) | Call sequence, arguments | Writes entry function calls | Must use `entry` or `public entry` functions |
| Object control | [which objects] | Owned: full control / Shared: read + mutate via public fns | [list constraints] |
| Signer control | Own address only | Cannot impersonate other signers | Single signer per tx (or multi-sig) |
| Type parameter control | `<T>` in generic calls | Can instantiate with any type meeting constraints | Ability constraints enforced |
| Call sequence control | Order of calls in PTB/script | Deterministic, attacker-chosen order | Within single tx only |
| Timing control | When to submit tx | Choose epoch/timestamp window | Cannot control exact consensus ordering |

**Critical question:** Does the attacker control enough surfaces simultaneously
to reach the vulnerable state AND extract value?
```

---

## Section 4: PoC Pseudocode Template

Write concrete exploit sequences, not vague descriptions.

### Sui PTB Format

```
### PoC: [finding title]

**Preconditions:**
- [Object X exists as shared object at 0x...]
- [Attacker owns Y tokens]
- [Protocol state: ...]

**PTB Sequence:**
1. MoveCall(pkg::module::function_a<TypeA>(shared_obj, arg1, arg2))
   → Returns: result_a
2. MoveCall(pkg::module::function_b(result_a, attacker_coin))
   → Returns: stolen_value
3. TransferObjects([stolen_value], attacker_address)

**Postconditions:**
- Attacker gains: [exact amount and asset]
- Protocol loses: [exact amount and asset]
- State corruption: [describe if any]

**Profit calculation:**
- Gross profit: [amount]
- Gas cost: ~[amount] SUI
- Net profit: [amount]
```

### Aptos Transaction Script Format

```
### PoC: [finding title]

**Preconditions:**
- [Resource R exists at address 0x...]
- [Attacker has account with ...]

**Transaction sequence:**
Tx 1:
  entry fun setup(signer: &signer) {
      module::function_a<TypeA>(signer, arg1, arg2);
  }

Tx 2:
  entry fun exploit(signer: &signer) {
      let value = module::function_b(signer, arg3);
      coin::deposit(signer::address_of(signer), value);
  }

**Postconditions:**
- Attacker gains: [exact amount]
- Victim loses: [exact amount]
```

---

## Section 5: Negative PoC Template

When dismissing a finding, prove it's NOT exploitable.

```
### Negative PoC: [finding title]

**Claimed vulnerability:** [what the finding alleges]

**Normal operation trace:**
1. User calls function_a(args) → [state changes]
2. Internal: assert!(condition) at line NN → passes because [reason]
3. Result: [expected behavior]

**Attempted exploit trace:**
1. Attacker calls function_a(malicious_args) → [state changes]
2. Internal: assert!(condition) at line NN → **FAILS** because [reason]
3. Transaction aborts. No state corruption.

**Precondition gap:**
The exploit requires [state X], but:
- [State X] is set only in `init()` at `file.move:NN`
- `init()` enforces [constraint] via assert at line NN
- Therefore [state X] is unreachable through valid protocol operations

**Conclusion:** Finding DISMISSED — [precondition unreachable / blocked by assert /
type system prevents / ownership model prevents]
```

---

## Section 6: Devil's Advocate Evidence Template

Structured challenge protocol. Answer 11 questions AGAINST the finding, then 2 FOR
it (to prevent false negatives from overzealous dismissal).

### Questions AGAINST the Finding (try to disprove it)

```
### Devil's Advocate: [finding title]

**Against:**
1. Does Move's type system already prevent this?
   → [answer with specific ability/constraint]

2. Does an upstream caller already validate this input?
   → [trace callers, cite file:line]

3. Is the "vulnerable" branch actually reachable?
   → [trace all paths that set the condition variable]

4. Does a downstream assert/abort already block the exploit?
   → [cite the assert, explain why it fires]

5. Does object ownership make this infeasible?
   → [Sui: owned vs shared; Aptos: signer requirement]

6. Does the attacker actually profit after gas + fees?
   → [calculate cost vs gain]

7. Can the attacker actually obtain the required capability/object?
   → [trace capability creation and distribution]

8. Is this a known-safe design pattern? (Check DESIGN-L1 to L4)
   → [cite the pattern if applicable]

9. Would my recommended fix actually change behavior?
   → [apply fix mentally, compare outcomes]

10. Am I applying a Solidity mental model to Move?
    → [list Move-specific properties that differ]

11. Does the code I'm citing actually say what I think?
    → [re-read it now, quote the exact line]
```

### Questions FOR the Finding (prevent false negatives)

```
**For:**
12. If I'm wrong about the protection, what's the worst case?
    → [describe maximum impact if the protection fails]

13. Is there a code path that BYPASSES the protection I identified?
    → [check all callers, all entry points, admin overrides]
```

### Decision

```
**Verdict:** VALID / QUESTIONABLE / DISMISSED
**Strongest argument against:** [#N — one-line summary]
**Strongest argument for:** [#12 or #13 — one-line summary]
**Confidence:** confirmed / likely / needs_review
```
