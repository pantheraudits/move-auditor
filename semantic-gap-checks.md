# Semantic Gap Checks

Use this file for protocols with:

- rewards or accumulators
- checkpoints or snapshots
- cross-module accounting
- lending / vault / staking / liquidation state

This pass is designed to catch subtle state bugs that normal pattern scans miss.

## Gap Types

- `SYNC_GAP`: one accounting variable updates, its mirror does not
- `CONDITIONAL_SKIP`: checkpoint or accumulator updates only on one branch
- `ACCUMULATION_EXPOSURE`: time-weighted or rate-weighted state can be manipulated before snapshot
- `LIFECYCLE_GAP`: one module closes state while another still depends on it
- `DUAL_SOURCE_METRIC`: the same invariant is checked against different data sources

## Workflow

For each candidate gap:

1. identify the writer path
2. identify the skipped or missing sibling path
3. identify every consumer of the stale state
4. measure persistence: same tx / next tx / unbounded / permanent
5. quantify the wrong outcome with a numeric trace

If you cannot name both:

- the writer path
- the stale consumer path

do not escalate beyond `QUESTIONABLE`.

## High-Signal Targets

Always run this pass on lending, staking, reward, vault, liquidation, and oracle-heavy protocols.

Search especially for:

- `reward_per_share`
- `accumulator`
- `checkpoint`
- `last_update`
- `index`
- `total_debt`
- `borrow_amount`
- `cash_reserve`
- `emode`
- `claimable`

## Mandatory Checks

### Mirror Variable Consistency

If two variables represent the same economic concept at different scopes, verify
every path that changes one also changes the other.

### Conditional Checkpoint Writes

For every conditional write to a checkpoint or accumulator:

- can the false branch happen in production?
- who later reads the stale value?
- does that stale read affect debt, rewards, collateral, shares, or liquidation?

### Pre-Accrual Before Config Changes

Before changing:

- interest model
- fee rate
- reward rate
- liquidation threshold

verify accrued state is settled first.

### Cross-Module Cleanup Completeness

When an entity is repaid, liquidated, closed, or deleted, verify dependent modules
clean up trackers, rewards, dynamic fields, receipts, and checkpoints.

### Deviation Reference Freshness

If a deviation or sanity check exists, verify the reference point is:

- fresh
- not trivially admin-manipulable
- not updated only on a rare path

## Output Template

```md
### Gap Summary
- Gap Type: `...`
- Stale Variable(s): `...`
- Writer Path: `module::function`
- Consumer Path: `module::function`
- Persistence: same tx / next tx / unbounded / permanent

### Numeric Trace
1. Initial state: ...
2. Gap-creating action: ...
3. Stale read: ...
4. Wrong outcome: ...
```
