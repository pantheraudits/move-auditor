# Move Auditor Skill Benchmark — OpenZeppelin Contracts for Sui

> **Protocol**: OpenZeppelin Contracts for Sui — Move library suite (access control + math)
> **Code**: https://github.com/OpenZeppelin/contracts-sui
> **Model**: Claude Opus 4.6 max
> **Date**: 2026-03-24
> **Tools compared**: `pantheraudits/move-auditor` · `Monethic/monethic-maia` (MAIA) · Raw Claude CLI (no skill)

---

## Codebase Summary

| Metric | Value |
|---|---|
| Chain | Sui Move |
| Source files | 19 |
| Source LoC | ~5,500 |
| Test files | 42 |
| Packages | `openzeppelin_access`, `openzeppelin_math`, `openzeppelin_fp_math` |
| Entry points | 0 `entry fun` — all `public fun` (library-only) |
| Nature | Composable library — no protocol logic, no DeFi state |

---

## Ground Truth — 12 Verified Findings (Manual Verification)

All findings were manually verified against source code at commit `7cfc07c`. Since this is a library codebase (not a contest), ground truth was established through independent code review rather than from known issues.

**Verdict: 0 Critical, 0 High, 0 Medium, 3 Low, 9 Informational — zero exploitable bugs.**

| ID | Description | File | Verified Severity |
|---|---|---|:---:|
| VF-1 | Missing descriptive error on div-by-zero in fixed-point `div`/`mod` — relies on opaque VM abort instead of `EDivideByZero` like core math module | `ud30x9_base.move:287`, `sd29x9_base.move:312` | Low |
| VF-2 | No minimum bound on `min_delay_ms` — allows zero-delay wrap defeating time-lock purpose | `delayed.move:114` | Info |
| VF-3 | No upper bound on `min_delay_ms` — near-`u64::MAX` value causes overflow abort in `schedule_transfer`, permanently locking wrapped object | `delayed.move:214,246` | Low |
| VF-4 | Shared-object executor can bind cancel authority via `ctx.sender()` — documented design constraint with 3 security warnings | `two_step.move:254` | Info |
| VF-5 | `PendingOwnershipTransfer` shared object permanently orphaned if both `from` and `to` lose access — no timeout mechanism | `two_step.move:267` | Info |
| VF-6 | `casting_u128::into_UD30x9` name misleadingly suggests scaling but is just `wrap()` — `into_UD30x9(42)` gives `0.000000042` not `42.0` | `casting/u128.move:13` | Low |
| VF-7 | Quicksort `O(n^2)` worst-case gas consumption — documented, mitigated by median-of-three | `vector.move:64` | Info |
| VF-8 | `pow()` uses `O(n)` repeated multiplication with compounding truncation error — documented, intentional for truncation semantics | `ud30x9_base.move:313`, `sd29x9_base.move:343` | Info |
| VF-9 | `borrow_mut`/`borrow_val` allows unrestricted mutation of wrapped object during pending delayed transfer — by design, owner has custody | `delayed.move:153` | Info |
| VF-10 | Fixed-point `mul`/`div` truncate toward zero without rounding option — industry standard, documented | `sd29x9_base.move:291`, `ud30x9_base.move:266` | Info |
| VF-11 | Two-step transfer accept/cancel race on shared object — intended security property (owner retains cancel rights) | `two_step.move:267` | Info |
| VF-12 | `cancel_schedule` works after delay elapses — delay provides observation time, not binding commitment | `delayed.move:342` | Info |

---

## Finding Coverage

| ID | Verified Finding | `move-auditor` | MAIA | Raw Claude CLI |
|---|---|:---:|:---:|:---:|
| VF-1 | Missing descriptive div-by-zero in FP ops | ✅ Low | ❌ | ❌ |
| VF-2 | No minimum bound on `min_delay_ms` | ✅ Low | ✅ Low | ✅ Medium |
| VF-3 | No upper bound on `min_delay_ms` / overflow lock | ❌ | ✅ Low | ⚠️ Medium* |
| VF-4 | Shared-object executor binds cancel authority | ✅ Info | ✅ Medium | ✅ Medium |
| VF-5 | Orphaned `PendingOwnershipTransfer` | ✅ Info | ✅ Low | ✅ Info |
| VF-6 | `into_UD30x9` misleading name | ❌ | ❌ | ✅ Low |
| VF-7 | Quicksort `O(n^2)` worst-case | ✅ Info | ❌ | ✅ Low |
| VF-8 | `pow()` compounding truncation | ✅ Info | ❌ | ✅ Low |
| VF-9 | `borrow_mut` during pending transfer | ❌ | ✅ Info | ❌ |
| VF-10 | `mul`/`div` truncation (no rounding option) | ✅ Info | ✅ Info | ❌ |
| VF-11 | Accept/cancel race | ✅ Info | ✅ Info | ❌ |
| VF-12 | `cancel_schedule` after delay elapses | ❌ | ❌ | ✅ Info |
| **Score** | | **8 / 12** | **7 / 12** | **7 / 12** |

> ⚠️ Raw CLI M-1 described wrong overflow mechanism — claimed Move "wraps" on overflow when it actually **aborts** (checked arithmetic). The permanent-lock effect is real but the technical explanation is incorrect.

---

## False Positive Analysis

| Tool | Total Reported | Valid | False Positives | FP Rate |
|---|:---:|:---:|:---:|:---:|
| `move-auditor` | 7 | 7 | 0 | **0%** |
| MAIA | 8 | 7 | 1 | **12.5%** |
| Raw Claude CLI | 9 (non-info) | 7 | 2 | **22.2%** |

### False Positive Details

| Tool | Finding | Why It's a False Positive |
|---|---|---|
| MAIA | CF-008: SD29x9 `pow()` uses `<=` instead of `<` | The `<=` is correct — must allow `res_mag == 2^127` for the legitimate negative minimum case (`-2^127`). Changing to `<` would break valid computations. `wrap_components` correctly handles the final range check. |
| Raw CLI | M-4: Transfer to `@0x0` = permanent loss | `@0x0` is a valid Sui address (framework address). Checking it specifically wouldn't prevent transfers to any other uncontrolled address. Self-inflicted by owner across two deliberate calls with delay. MAIA correctly rejected this as FP-16. |
| Raw CLI | M-1: Overflow mechanism error | Claimed Move "wraps" on overflow — Move uses **checked arithmetic** and aborts. The permanent-lock effect is real but the technical analysis is factually wrong. Counted as partial (found the effect, wrong mechanism). |

### MAIA Internal Triage Quality

MAIA's pipeline deserves special note: it generated 73 raw findings, deduplicated to 26, and rejected 18 as false positives — **all 18 rejections were correct**. Notable correct rejections:

| FP ID | What Raw CLI reported as | MAIA's correct rejection rationale |
|---|---|---|
| FP-16 | M-4 (Medium) | `@0x0` valid on Sui; `cancel_schedule` provides safety net |
| FP-17 | — | Push-based transfer is the design; two-step exists for pull-based |
| FP-10 | L-3 (Low) | Library macro, documented worst-case, gas metering bounds execution |
| FP-12 | — | Hot potato + ID checks + Move type system = sufficient safety |

---

## Severity Accuracy

How accurately each tool classified the findings it found (compared to verified severity):

| Tool | Exact Match | Over by 1 | Over by 2+ | Accuracy |
|---|:---:|:---:|:---:|:---:|
| `move-auditor` | 7 / 8 | 1 / 8 | 0 / 8 | **87.5%** |
| MAIA | 4 / 7 | 2 / 7 | 1 / 7 | **57.1%** |
| Raw Claude CLI | 2 / 8 | 3 / 8 | 3 / 8 | **25.0%** |

### Severity Misclassifications

| Tool | Finding | Reported | Verified | Delta |
|---|---|:---:|:---:|:---:|
| `move-auditor` | VF-2 (zero delay) | Low | Info | +1 |
| MAIA | VF-2 (zero delay) | Low | Info | +1 |
| MAIA | VF-4 (shared executor) | Medium | Info | +2 |
| MAIA | VF-5 (orphaned transfer) | Low | Info | +1 |
| Raw CLI | VF-2 (zero delay) | Medium | Info | +2 |
| Raw CLI | VF-3 (overflow lock) | Medium | Low | +1 |
| Raw CLI | VF-4 (shared executor) | Medium | Info | +2 |
| Raw CLI | VF-7 (quicksort) | Low | Info | +1 |
| Raw CLI | VF-8 (pow truncation) | Low | Info | +1 |
| Raw CLI | VF-12 (cancel after delay) | Low | Info | +1 |

> Raw Claude CLI reported **4 Medium findings** when the verified ground truth contains **zero Mediums**. This indicates a systematic tendency to over-classify severity.

---

## Summary Scorecard

| Metric | `move-auditor` | MAIA | Raw Claude CLI |
|---|:---:|:---:|:---:|
| Findings found | **8 / 12** | 7 / 12 | 7 / 12 |
| False positive rate | **0%** | 12.5% | 22.2% |
| Severity accuracy | **87.5%** | 57.1% | 25.0% |
| Factual errors | **0** | 0 | 1 (Move overflow) |
| Unique valid finds | 1 (VF-1) | 1 (VF-9) | 2 (VF-6, VF-12) |
| Highest false severity | Low (1x) | Medium (1x) | Medium (4x) |
| Internal FP filtering | N/A | 18/18 correct | N/A |
| Report quality | Structured, clean | Most thorough | Over-stated conclusions |

---

## Verdict

| Rank | Tool | Reason |
|:---:|---|---|
| 🥇 | **`move-auditor`** | Best coverage (8/12), **zero false positives**, best severity accuracy (87.5%), found the only unique Low nobody else caught (div-by-zero inconsistency), no factual errors |
| 🥈 | **MAIA** | Strong coverage (7/12), excellent internal triage pipeline (18/18 correct FP rejections), most thorough report with detailed reasoning. Loses points for 1 FP (CF-008) and over-classifying CF-001 as Medium despite 3 security warnings in code |
| 🥉 | **Raw Claude CLI** | Same coverage (7/12) but worst severity accuracy (25%), 1 factual error about Move semantics, 2 false positives, and 4 findings at Medium when ground truth has zero Mediums. Found 2 unique issues (VF-6, VF-12) but offset by unreliable classifications |

---

## Key Observations

### What Every Tool Agreed On
All three tools correctly identified that this is a well-engineered library with no exploitable vulnerabilities. The zero-delay and shared-object executor findings were found by all three, confirming these are the most surface-level observations.

### What Only One Tool Found

| Finding | Tool | Why Others Missed It |
|---|---|---|
| VF-1: div-by-zero inconsistency | `move-auditor` | Requires comparing fixed-point module against core math module's `EDivideByZero` pattern — cross-module consistency check. **Submitted upstream and merged: [OpenZeppelin/contracts-sui#263](https://github.com/OpenZeppelin/contracts-sui/pull/263)** |
| VF-6: `into_UD30x9` naming | Raw CLI | API usability concern requiring understanding of the `wrap()` vs scaling distinction |
| VF-9: `borrow_mut` during transfer | MAIA | Requires reasoning about state visibility guarantees during delay windows |

### Patterns in Tool Behavior

| Pattern | Observation |
|---|---|
| **Severity inflation** | Raw CLI inflated every finding by 1-2 severity levels. All 4 "Mediums" should be Info or Low. |
| **Mechanism accuracy** | Raw CLI claimed Move wraps on overflow — a fundamental misunderstanding of Move's checked arithmetic. move-auditor and MAIA correctly described Move semantics. |
| **FP filtering** | MAIA's pipeline (73 → 26 → 8) demonstrates structured triage. Raw CLI had no filtering — everything it thought of was reported. |
| **Conservative vs. aggressive** | move-auditor was most conservative (no over-classification beyond +1). Raw CLI was most aggressive (systematic +2 inflation). |
| **Documentation awareness** | move-auditor and MAIA correctly recognized documented design choices. Raw CLI repeatedly flagged documented behavior as bugs. |

### Codebase Assessment (All Tools Agree)

The OpenZeppelin Contracts for Sui library is production-quality code:
- Excellent documentation with explicit security warnings
- Strong use of Sui patterns (hot potato, no `store` on wrappers)
- Correct math across overflow/underflow/rounding edge cases
- Healthy test-to-source ratio (~2.2:1 for test files to source files)
- Zero exploitable vulnerabilities found by any tool

---

### Upstream Contribution

The unique `move-auditor` find (VF-1: missing `EDivideByZero` guard) was submitted as a fix to OpenZeppelin and **merged** — [OpenZeppelin/contracts-sui#263](https://github.com/OpenZeppelin/contracts-sui/pull/263). This makes `move-auditor` a contributor to OpenZeppelin's Sui contracts.

---

*All findings manually verified against source at commit `7cfc07c`. Ground truth established through independent code review.*

> **Note:** This benchmark may not be 100% accurate. If you spot any mistakes, have questions, or believe something is incorrect, please reach out on X ([@thepantherplus](https://x.com/thepantherplus)) so it can be corrected.
