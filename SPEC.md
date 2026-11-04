# Contract and input specification

The version 1 suite is a JSON object with `schema_version: 1`, `rules` and
`cases`. Unknown keys are rejected. `examples/lab-healthy.json` is a complete
multi-rule example. Each rule has an ID, a window in seconds and a list of
stages. A stage has an event kind, a dotted join field path, an optional source
and optional exact-equality predicates in `where`. Predicates compare JSON
types exactly. Paths walk objects only. The same join value must be present at
all stages, but the paths can differ to support schemas with different subject
roles, such as a login target and an IAM actor.

Each case supplies a name, an inclusive arrival deadline, baseline and candidate
events, and a map of rule IDs to expectations. Each expectation supplies a boolean
`detected`. Positive expectations may also supply `terminals`, the exact set of
final-stage event IDs, and `max_lag`, the maximum allowed lag for every selected
proof. The gate rejects a baseline that violates its label or evidence constraints.
The benchmark uses the baseline as its control and applies the specified mutation.

## Events and clocks

The canonical envelope has `id`, `kind`, `time` and `arrival`, with optional
`identity`, `source` and `fields`. Time and arrival are nonnegative integer
seconds on the same clock. Arrival must be at or after event time. The reference
runner sorts by event time and breaks ties by event ID. Stage times must increase
strictly. The rule window includes its upper bound and spans first to last event.
An event arriving after the case deadline is excluded from all stage matches.

Replays select one deterministic proof for each qualifying terminal. The
frontier favors the most recent start that still satisfies the sequence, with
stable tie handling. Readiness is the latest arrival among the chosen proof
events. Lag is readiness minus the terminal event timestamp. This measure
describes the selected proof and can differ from the earliest possible proof
arrival or an actual SIEM scheduling delay.

Events can be inline arrays or references relative to the suite:

```json
{"file":"lab-exports/google-positive.jsonl","format":"google-secops-lab"}
```

| Format | Inputs |
| --- | --- |
| `canonical` (default) | JSON array of canonical envelopes |
| `mapped-jsonl` | JSON objects per line, with a `mapping` object in the file reference |
| `sentinelops-rba` | Synthetic SentinelOps RBA dataset document |
| `google-secops-lab` | Synthetic JSONL from Google SecOps Lab's normalize command |

Mapped JSONL requires source paths for ID, kind, time and arrival. It accepts
optional source and identity paths and up to 32 field aliases. Clock is
`rfc3339` by default or `unix-seconds`. RFC3339 values require an explicit
timezone and are floored to integer seconds. Lab adapters likewise floor
timestamps and use event time as arrival, because the lab exports contain no
independent delivery clock. Add delays through the benchmark or use a mapped
export with real arrival timestamps.

```sh
python -m detcontinuity adapt mapped-jsonl examples/lab-exports/ecs-positive.jsonl --mapping examples/ecs-mapping.json
```

## Failure and report semantics

| Result | Meaning |
| --- | --- |
| `invalid_baseline` | Baseline contradicts the independent case label or evidence constraint |
| `regression` | Baseline passes and candidate violates one or more expectations |
| `pass` | Both observations meet the expectation |

JSON preserves both sets of matched IDs, stage counters and up to five
sample event IDs per rejection reason and stage. Counters are
stage-local and record the first rejection reason in evaluation order. Thus a
late event with a missing join is counted as late. An absent stage has no
`seen` count. Counters show observed symptoms and do not identify a unique
root cause. Fingerprints cover raw suite bytes and the canonical rules and
deduplicated inputs. They are integrity aids, without a signature or identity
attestation. Store reports according to the sensitivity of the supplied IDs.

The benchmark emits TP/FP/FN/TN counts at the rule/case level. Its exit code
is 0 when the experiment completes with valid baselines, including when faults
cause regressions. An invalid baseline exits 1. A no-op fault exits 2 so a
fault that never changed any record cannot be mistaken for resilience.

Each fault specifies one event kind. Available operations are `drop_kind`,
`drop_field` with a field path, `replace_field` with a path and string value,
`delay` with positive seconds, and `sample` with an interval of at least two.
Sampling retains the first matching event and then every Nth matching event
in canonical event-time order. Faults are independent and each starts from
the same baseline.

Limits per invocation include 32 MiB per file, 50,000 records per event list,
200,000 deduplicated materialized records, 64 rules, 128 cases and 500,000
event/rule evaluations across a benchmark. Contradictory records sharing an ID
and duplicate JSON object keys fail validation. JSONL and JSON are loaded into
bounded memory for offline CI use. Split large corpora into scenario suites.
