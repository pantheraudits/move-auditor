# Move Auditor Skill Benchmark — CurrenSui Lending Protocol

> **Protocol**: CurrenSui — Sui Move lending protocol  
> **Contest**: Sherlock, 6,470 nSLOC, March 2026  
> **Date**: 2026-03-11  
> **Commit audited**: `dc2975d`  
> **Tools compared**: `pantheraudits/move-auditor` · `forefy/.context` · Raw Claude CLI (no skill)

---

## Ground Truth — 6 Confirmed Known Issues

| ID | Description | File | Severity |
|---|---|---|:---:|
| KI-1 | eMode stale aggregate → borrow cap silently exceeded | `emode.move:183` | High |
| KI-2 | `deposit_limit_breached` double-subtracts `cash_reserve` | `reserve.move:89` | High |
| KI-3 | `update_market_asset_interest_model` missing pre-accrual → retroactive rate | `market.move` | High |
| KI-4 | ADL uses `reserve.debt()` instead of `emode_group.borrow_amount()` → wrongful liquidation | `adl.move` | High |
| KI-5 | `liquidate_ctokens` reverts at high utilization → bad debt accumulates | `reserve.move:171` | High |
| KI-6 | `repay_on_behalf` orphans reward tracker → admin reward pool permanently locked | `repay.move` + `liquidity_mining.move` | High |

---

## Known Issue Coverage

| ID | Known Issue | `move-auditor` | `forefy/.context` | Raw Claude CLI |
|---|---|:---:|:---:|:---:|
| KI-1 | eMode stale aggregate borrow cap bypass | ✅ | ❌ | ✅ |
| KI-2 | `deposit_limit_breached` double-subtraction | ✅ | ❌ | ❌ |
| KI-3 | Retroactive interest rate — missing pre-accrual | ❌ | ❌ | ❌ |
| KI-4 | ADL wrong debt source → wrongful liquidation | ❌ | ❌ | ⚠️ Partial |
| KI-5 | Liquidation reverts at high utilization | ❌ | ❌ | ❌ |
| KI-6 | `repay_on_behalf` orphans reward tracker | ❌ | ⚠️ Partial* | ❌ |
| **Score** | | **2 / 6** | **0 / 6** | **1 / 6** |

> ⚠️ Partial = found the function but diagnosed the wrong root cause

---

## False Positive Rate

| Tool | Reported | Valid | False Positives | FP Rate |
|---|:---:|:---:|:---:|:---:|
| `move-auditor` | 4 | 2 | 1 Low/Info* | ~25% |
| `forefy/.context` | 5 | 0 | 5 | 100% |
| Raw Claude CLI | 5 | 1–2 | 3 | ~60% |

> *N-1 (partial liquidation skips `min_borrow_amount`) is a real code defect, Low/Info severity — not a hallucination, just over-classified one level

---

## Summary Scorecard

| Metric | `move-auditor` | `forefy/.context` | Raw Claude CLI |
|---|:---:|:---:|:---:|
| Known issues found | **2 / 6** | 0 / 6 | 1 / 6 |
| False positive rate | **~25%** | 100% | ~60% |
| Severity accuracy | Conservative | N/A | Correct |
| First-run reliability | Needed re-prompt | ✅ | ✅ |
| Run time | ~45 min | 25 min | 49 min |

---

## Verdict

| Rank | Tool | Reason |
|:---:|---|---|
| 🥇 | **`move-auditor`** | Best coverage (2/6), lowest FP rate, zero hallucinated bugs |
| 🥈 | Raw Claude CLI | Correct on what it found, but 5/6 missed and high FP rate |
| 🥉 | `forefy/.context` | 100% FP rate — triage correctly rejected all 5, but underlying audit found nothing valid |

---

## Patterns Every Tool Missed

| Gap | Affects | Description |
|---|---|---|
| Admin setter without pre-state-sync | KI-3 | Rate model update without prior `accrue_interest()` applies new rate retroactively |
| Cross-module lifecycle cleanup | KI-6 | Permissionless repay creates orphaned tracker in a separate rewards module |
| Cash availability before liquidation | KI-5 | `liquidate_ctokens` calls `balance.split()` without checking idle cash ≥ seize amount |
| Dual-source metric consistency | KI-4 | ADL entry check and stop check read total debt from different sources |

---

*All findings manually verified against source at commit `dc2975d`.*
