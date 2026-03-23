# Move Auditor Benchmarks

Comparative benchmarks measuring `move-auditor` against other AI audit tools on real Sui Move codebases.

---

## Benchmarks

| # | Target | Type | LoC | Tools Compared | Result |
|---|---|---|:---:|---|:---:|
| 1 | [CurrenSui Lending](BENCHMARK-currensui.md) | DeFi protocol (Sherlock contest) | 6,470 | `move-auditor` vs `forefy/.context` vs Raw CLI | 🥇 move-auditor |
| 2 | [OpenZeppelin Contracts](BENCHMARK-openzeppelin.md) | Library (hardened, no exploitable bugs) | 5,500 | `move-auditor` vs `MAIA` vs Raw CLI | 🥇 move-auditor |

---

## Aggregate Results

| Metric | `move-auditor` | Competitors (best) |
|---|:---:|:---:|
| Bug coverage | **8/12, 2/6** | 7/12, 1/6 |
| False positive rate | **0% – 25%** | 12.5% – 100% |
| Severity accuracy | **87.5%** | 57.1% |
| Factual errors | **0** | 1 (Move overflow semantics) |

---

### What each benchmark tests

- **CurrenSui** — Can the tool find real High-severity bugs in a complex DeFi lending protocol? Ground truth from Sherlock contest known issues.
- **OpenZeppelin** — Can the tool accurately assess a hardened library without hallucinating bugs? Tests false positive discipline and severity calibration on production-quality code.

Together they measure both **recall** (finding real bugs) and **precision** (not inventing fake ones).
