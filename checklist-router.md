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
- `move-fp-catalog.md`

## Verification Phase Loading

Load these files when entering Phase 7 — Verify & Triage:

- `evidence-chains.md` — structured evidence templates for data flow, math proofs, PoC
- `confidence-gates.md` — confidence gating, hard evidence requirements per finding type

## Chain Routing

| Signal | Load |
|--------|------|
| `sui::object`, `sui::transfer`, `sui::tx_context`, `UID` | `sui-patterns.md` |
| `aptos_framework`, `aptos_std`, `#[test_only]`, `SignerCapability`, `fungible_asset` | `aptos-patterns.md` |

## Protocol Routing

| Signal | Load | Follow-up |
|--------|------|-----------|
| `borrow`, `repay`, `withdraw`, `deposit`, `collateral`, `health_factor`, `margin`, `risk_ratio`, `leverage`, `limiter`, `rate_limit`, `outflow` | `defi-vectors.md`, `defi/defi-lending.md` | cross-module interaction scan + DEFI-90 limiter netting scan |
| `liquidat`, `seize`, `bad_debt`, `insurance`, `self_match` | `defi/defi-liquidation.md` | idle-cash and price-source checks |
| `oracle`, `pyth`, `switchboard`, `price_feed`, `twap` | `defi/defi-oracle.md` | stale/deviation audit |
| `reward_per_share`, `accumulator`, `claim`, `stake`, `unstake`, `reward_manager`, `pool_reward`, `liquidity_mining`, `total_rewards` | `defi/defi-staking.md`, `defi/defi-math-precision.md`, `semantic-gap-checks.md` | checkpoint/accumulator review + **mandatory DEFI-85/86 fixed-point overflow check** |
| `swap`, `pool`, `lp`, `min_amount_out`, `slippage` | `defi/defi-slippage.md` | PTB / multi-hop review |
| `ed25519`, `secp256k1`, `verify_signature`, `nonce`, `threshold`, `signers`, `quorum`, `multisig`, `approvers`, `guardians` | `defi/defi-signatures.md` | replay / domain separation review + **policy-snapshot review (DEFI-89): if signatures are checked against a mutable signer-set/threshold/quorum, confirm the signed message binds a policy version/nonce** |
| `bridge`, `wormhole`, `vaa`, `emitter`, `chain_id`, `cross-chain`, `recipient`, `payload`, `DepositRequest`, `WithdrawRequest` | `defi-vectors.md` | DEFI-10 bridge message / recipient-semantic review |

## Feature Flags

| Signal | Action |
|--------|--------|
| `dynamic_field`, `dynamic_object_field`, `object::new`, `object::delete` | force object lifecycle cleanup review |
| Sui `transfer::share_object`, `public_share_object`, or `share_object` on any `has key` struct | force **stale-package surface review (SUI-23)** — every public/entry/`public(package)` function taking `&T` or `&mut T` must assert `version == CURRENT_VERSION`; missing version field on the shared struct = Critical; old package versions remain callable forever (Scallop class) |
| Sui `public fun` mutates state | force PTB composability review |
| Sui `has key` struct with an inline collection field (`vector<…>`, `VecMap`, `VecSet`) grown by a public/entry path | force **object-size DoS review (SUI-45)** — inline collections inflate the object toward `max_move_object_size` (~256KB); if growth is permissionless and uncapped the object eventually bricks all writes. Flag redundancy with any existing `Table`/`Bag` |
| `MASK`, `_MASK`, `SHIFT`, `_SHIFT`, `BITS`, `bitmap`, `bitset`, `flags`, `packed`, `bucket`, `slot`, or repeated bitwise `&` / `|` / `<<` / `>>` around counters | force **packed-field mask-width review (common-move.md 2.8)** — derive each field's bit width, distinguish max index from max count, and test power-of-two boundary values like 16 decoding through getters |
| `fixed_point`, `decimal`, `wad`, `ray`, `float`, custom `Decimal` / `WAD` / `Float` wrapper, any `from().mul()` or `.mul().div()` chain | force fixed-point helper inspection + load `defi/defi-math-precision.md` |
| `last_update`, `checkpoint`, `index`, `cumulative` | load `semantic-gap-checks.md` |
| `limiter`, `rate_limit`, `outflow`, `inflow`, `segment_duration`, `cycle_duration`, `bucket` | load `defi/defi-lending.md` and force **rolling net-outflow limiter rollover review (DEFI-90)** |
| `rate_model`, `interest_model`, `reward_rate`, `fee_rate` admin setters | force pre-accrual review |
| `clock::timestamp_ms` combined with oracle timestamps | force unit-conversion review |

## Escalation Rules

- If lending is detected, run both semantic-gap and cross-module interaction review.
- If segmented limiter signals are detected, run DEFI-90: add usage before a segment boundary, reduce after rollover, and confirm live usage returns to zero.
- If oracle is detected, always check stale price, deviation reference, and liquidation price-source consistency.
- If Sui stateful `public fun` is detected, think in PTB sequences, not single-call flows.
- **If any reward/accumulator/checkpoint pattern is detected**, force DEFI-85/86 + 12.1 checkpoint deadlock analysis. This is the **#1 missed bug class** in Move audits. Open every fixed-point helper, derive overflow bounds, compute threshold table, and apply the Recoverability Matrix.
- If any fixed-point/decimal/float helper library exists in the codebase, you MUST open and read its `mul`, `div`, `from` functions before completing Phase 3. Do not rely on calling code — inspect the helper internals.
- **If the chain is Sui AND any shared object exists**, run the SUI-23 stale-package detection ritual (list shared types → confirm `version` field → grep every public-surface function taking `&T`/`&mut T` → confirm version assertion). Treat **every historical package version** as live attack surface — bug fixes do NOT deprecate prior versions unless `CURRENT_VERSION` was bumped and `migrate` was run on every shared object. (Scallop, April 2026.)
- **If staking / reward-accumulator patterns are detected**, run the DEFI-88 ritual: for every per-user position struct with a `last_index` / `reward_debt` / `last_reward_per_share` / `last_cumulative` field, open every constructor and confirm the field is synced to the pool's *current* index — never left at 0. Verify across **all** package versions on Sui.
