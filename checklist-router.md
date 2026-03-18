# Checklist Router

Use this file at audit start to decide which deep-check files must be loaded.

The goal is simple: if the code exposes a signal, load the right reference file
and run the right follow-up check.

## Coverage Plan

Produce a short plan:

```md
### Coverage Plan
- Chain: Sui
- Signals: lending, oracle, accumulator, fixed-point
- Files loaded: `common-move.md`, `sui-patterns.md`, `defi/defi-lending.md`, ...
- Follow-ups: semantic-gap scan, fixed-point helper inspection, cross-module interaction scan
```

## Always Load

- `common-move.md`
- `verification-policy.md`
- `checklist-router.md`

## Chain Routing

| Signal | Load |
|--------|------|
| `sui::object`, `sui::transfer`, `sui::tx_context`, `UID` | `sui-patterns.md` |
| `aptos_framework`, `aptos_std`, `#[test_only]`, `SignerCapability`, `fungible_asset` | `aptos-patterns.md` |

## Protocol Routing

| Signal | Load | Follow-up |
|--------|------|-----------|
| `borrow`, `repay`, `collateral`, `health_factor` | `defi-vectors.md`, `defi/defi-lending.md` | cross-module interaction scan |
| `liquidat`, `seize`, `bad_debt`, `insurance` | `defi/defi-liquidation.md` | idle-cash and price-source checks |
| `oracle`, `pyth`, `switchboard`, `price_feed`, `twap` | `defi/defi-oracle.md` | stale/deviation audit |
| `reward_per_share`, `accumulator`, `claim`, `stake`, `unstake` | `defi/defi-staking.md`, `semantic-gap-checks.md` | checkpoint/accumulator review |
| `swap`, `pool`, `lp`, `min_amount_out`, `slippage` | `defi/defi-slippage.md` | PTB / multi-hop review |
| `ed25519`, `secp256k1`, `verify_signature`, `nonce` | `defi/defi-signatures.md` | replay / domain separation review |

## Feature Flags

| Signal | Action |
|--------|--------|
| `dynamic_field`, `dynamic_object_field`, `object::new`, `object::delete` | force object lifecycle cleanup review |
| Sui `public fun` mutates state | force PTB composability review |
| `fixed_point`, `decimal`, `wad`, `ray`, custom `Decimal` / `WAD` wrapper | force fixed-point helper inspection |
| `last_update`, `checkpoint`, `index`, `cumulative` | load `semantic-gap-checks.md` |
| `rate_model`, `interest_model`, `reward_rate`, `fee_rate` admin setters | force pre-accrual review |
| `clock::timestamp_ms` combined with oracle timestamps | force unit-conversion review |

## Escalation Rules

- If lending is detected, run both semantic-gap and cross-module interaction review.
- If oracle is detected, always check stale price, deviation reference, and liquidation price-source consistency.
- If Sui stateful `public fun` is detected, think in PTB sequences, not single-call flows.
