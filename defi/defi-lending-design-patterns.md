# Known-Good Lending Design Patterns (NOT Bugs)

These are established, intentional design patterns used by battle-tested lending protocols
(Compound, Aave, MakerDAO, and their Move forks). **Do NOT report these as vulnerabilities**
unless you can demonstrate why the specific protocol's context makes the pattern unsafe.

Load this file alongside `defi-lending.md` when auditing lending protocols. Cross-reference
every lending-related candidate finding against these patterns before labeling it VALID.

---

## DESIGN-L1 — Spot Prices for Liquidation Seize, EMA/TWAP for Eligibility

**Why it's correct:**
- **Eligibility check (is this position liquidatable?)** uses EMA/TWAP to resist flash
  crashes and oracle manipulation — a momentary price spike shouldn't trigger mass liquidations.
- **Seize calculation (how much collateral does the liquidator get?)** uses spot price because
  the liquidator must sell the seized collateral at current market price. Using EMA for seize
  would underpay liquidators, making liquidation unprofitable, leading to bad debt accumulation.

**This is how Compound, Aave, and most lending protocols work.**

**False positive pattern:** "Seize uses spot while eligibility uses EMA — inconsistent oracle usage!"

**When it IS a bug:** If the protocol documentation explicitly states both should use the same
oracle mode, or if the spot/EMA divergence creates an arbitrage where attackers can self-liquidate
at a profit during high volatility (cross-ref: DEFI-59).

**Caveat — Missing EMA-Spot Divergence Guard in Liquidation Path:**
While using spot for seize and EMA for eligibility is a valid design choice, the liquidation path should still enforce a MAXIMUM EMA-spot divergence tolerance. If borrow/withdraw operations enforce this tolerance (reverting when EMA and spot diverge by >X%), but liquidation does NOT, then during extreme volatility the liquidation path becomes the only functioning code path — and it operates with potentially arbitrarily stale or divergent prices. Consider: add a wider (but not unlimited) tolerance check for liquidation, e.g., 2x the borrow/withdraw tolerance.

---

## DESIGN-L2 — Flash Loan Not Updating Accounting Fields (cash/debt)

**Why it's correct:**
- Hot potato / receipt pattern guarantees repayment within the same transaction.
- The accounting field (e.g., `cash`, `total_borrows`) correctly reflects the post-repayment
  state because repayment is guaranteed by Move's type system — the receipt struct has no
  `drop` ability, so the transaction aborts if repayment doesn't happen.
- **Decrementing cash during flash loan would UNDERSTATE true reserves** and create an
  exploitable exchange rate depression during the flash loan window. Other users' share
  calculations would be temporarily wrong.

**False positive pattern:** "cash not decremented during flash loan — inflated exchange rate!"

**When it IS a bug:**
- If the receipt CAN be destroyed without full repayment (check receipt struct abilities)
- If the accounting field is read by OTHER functions in the same PTB/transaction between
  borrow and repay, and those functions make decisions based on the stale value
- If there is no receipt pattern and repayment is merely checked by balance comparison

Cross-ref: SUI-09 (hot potato), SUI-17 (hot potato state reset), DEFI-27 (loan closure)

---

## DESIGN-L3 — Blocking Borrows When Cash < Cash Reserve

**Why it's correct:**
- Protocol reserves (cash reserve ratio) must be maintained for withdrawal liquidity.
- When accumulated fees/interest exceed available cash, the protocol correctly blocks new
  borrows until deposits or repayments restore liquidity.
- This is protective behavior, not a DoS vulnerability. It resolves naturally via normal
  protocol operations (deposits, repayments, fee harvesting).

**False positive pattern:** "Underflow in borrow check causes DoS in high-utilization markets!"

**When it IS a bug:**
- If the underflow aborts with an unhelpful error instead of a clean "insufficient liquidity"
  message (informational, not a vulnerability)
- If the blocking condition can be triggered by an attacker at low cost to grief legitimate
  borrowers permanently (not just during natural high utilization)
- If repayment or deposit paths are ALSO blocked, creating a deadlock

---

## DESIGN-L4 — Asymmetric EMA/Spot Divergence Formulas

**Why it's correct:**
- Many protocols intentionally use formulas that are MORE restrictive during risky price
  movements (spot crashing below EMA, indicating potential manipulation or flash crash)
  and LESS restrictive during safe movements (spot rising above EMA, indicating organic
  price recovery).
- The asymmetry protects the protocol during the exact conditions when manipulation is
  most likely, while avoiding unnecessary restrictions during normal market movements.

**False positive pattern:** "Formula divides by wrong denominator — asymmetric tolerance
calculation!"

**When it IS a bug:**
- If the asymmetry direction is INVERTED (more permissive during crashes, more restrictive
  during recovery — backwards from the intended protection)
- If the formula produces values outside [0, 1] range for a tolerance check
- If there is no documentation or comment explaining the intentional asymmetry

---

## How to Use This File

When reviewing a lending protocol finding in Phase 5 (Verify & Triage):

1. Check if the finding matches any DESIGN-L pattern above
2. If it matches: verify the protocol's implementation actually follows the established
   pattern (not a broken variant)
3. If the implementation matches the pattern correctly → DISMISS the finding, citing
   the specific DESIGN-L reference
4. If the implementation deviates from the pattern in a meaningful way → proceed with
   the finding but note the deviation explicitly

**Key principle:** The burden of proof shifts when a pattern matches established protocol
design. Instead of proving the code is safe, you must prove why the established pattern
is unsafe in THIS specific context.
