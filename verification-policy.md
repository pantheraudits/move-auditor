# Verification Policy

Use this file during verification and triage.

Its job is simple:

- reduce weak dismissals
- force realistic exploitability checks
- make High/Critical findings more defensible

## Core Rule

Bias against **false dismissals**.

If a finding may be real but the refutation depends on weak evidence, keep it
as `QUESTIONABLE` rather than marking it `DISMISSED`.

## Evidence Tags

Tag every decisive claim with one of these:

| Tag | Meaning | Strong enough for `DISMISSED`? |
|-----|---------|--------------------------------|
| `[CODE]` | in-scope source code | Yes |
| `[TEST]` | existing tests in the audited repo | Yes, if exact behavior is covered |
| `[MOCK]` | test helper / fake dependency | No |
| `[DOC]` | spec, README, comments | No |
| `[EXT-UNVERIFIED]` | external package behavior not verified from source | No |
| `[PROD-SOURCE]` | verified published package source | Yes |
| `[PROD-STATE]` | production on-chain package/object/config state | Yes |

Use a short evidence table for non-trivial findings:

```md
### Evidence Audit
| Claim | Evidence | Tag |
|------|----------|-----|
| `borrow` is permissionless | `sources/lending.move:112` | `[CODE]` |
| external oracle rejects stale data | test helper | `[MOCK]` |
```

## Mock Rejection Rule

If a dismissal depends on `[MOCK]`, `[DOC]`, or `[EXT-UNVERIFIED]`, do not mark
the finding `DISMISSED`.

Mark it:

- `QUESTIONABLE` if the root cause still looks technically plausible
- `OVERCLASSIFIED` if the bug is real but the claimed impact is too high

## Feasibility Gates

Before keeping any finding at High/Critical, pass both gates below.

### Gate 1: Reachability

Identify:

- attacker-accessible entry point
- intermediate call path
- required signer / object / capability / resource
- why the attacker can actually obtain or invoke each prerequisite

If the path requires a trusted admin or an unobtainable capability, reclassify it.

### Gate 2: Math Bounds

Substitute realistic ranges into the bug-triggering expression:

- token decimals
- supply / TVL
- fee / interest / reward parameters
- time windows and stale periods
- liquidation bonuses / close factors / oracle precision

If the bug requires impossible values or blocked domains, do not keep the original severity.

## Severity Discipline

Only use High/Critical if you can name:

1. attacker path
2. victim
3. broken invariant
4. harmful postcondition

If one of those is missing, downgrade or keep as `QUESTIONABLE`.

## Move-Specific Refutation Checks

When trying to dismiss a finding, explicitly test whether it is already blocked by:

- linear resource semantics
- ability constraints
- module visibility
- Sui ownership rules
- Aptos signer / capability rules
- PTB limitations on non-`public` Sui functions
- overflow abort turning silent corruption into DoS

Tie every dismissal to exact local evidence.

## Required Verifier Output

For each finding that survives triage, include:

- exact bug statement
- attacker profile
- preconditions
- postconditions
- evidence audit
- `reachability=pass/fail`
- `math_bounds=pass/fail`
- final label: `VALID`, `QUESTIONABLE`, `DISMISSED`, or `OVERCLASSIFIED`
- severity rationale
