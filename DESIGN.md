# Detection Continuity design

## Operational use case

A detection engineer proposes an ingestion filter, parser revision or SIEM migration.
CI runs labeled scenarios through the approved and proposed configurations. Each
pipeline exports the fields required by the contract. The gate compares both
results with the scenario label and gives reviewers the matched evidence,
arrival cutoff and input fingerprint. A baseline that contradicts the scenario
label is an invalid experiment and blocks the gate.

## How this extends the portfolio

SentinelOps MXDR exercises rule, health and response contracts. Google SecOps Lab
demonstrates normalization and a sensitive IAM investigation. ForgeSOC implements
the detection platform itself. Detection Continuity sits at the release boundary
between telemetry and detection. Its unit of evaluation is a proposed change
and its impact on a known attack or benign scenario.

Microsoft Sentinel exposes connector health and Google SecOps Health Hub exposes
ingestion and parsing health. Splunk Content Control supports detection testing.
The experiment here is a portable before/after contract that runs locally and
can explain why the same volume of data produces different detection results.

- [Microsoft Sentinel connector health](https://learn.microsoft.com/en-us/azure/sentinel/monitor-data-connector-health)
- [Google SecOps ingestion metrics](https://docs.cloud.google.com/chronicle/docs/ingestion/understand-ingestion-metrics)
- [Splunk Content Control](https://github.com/splunk/contentctl)

## Milestones and acceptance criteria

1. **Offline reference gate.** Reproduce late delivery, missing identity, missing
   source and identity collapse from a synthetic fixture. Fail deterministically
   with event-level evidence. Delivered in this directory.
2. **Pipeline integration.** Delivered for the two lab export formats and for
   mapped JSONL. The healthy and drift fixtures exercise the same labeled Google
   scenario with and without the actor field. CI runs the integration cases.
3. **Change impact.** Delivered as a static dependency lookup by kind and field.
   It identifies rule stages using a field, including parent objects. The
   benchmark measures those dependencies empirically with controlled mutations.
4. **Benchmark.** Delivered with two independent rule contracts, paired synthetic
   positives and negatives, six fault configurations and a JSON/HTML scorecard.
   The local test suite independently compares the sequence engine with an
   exhaustive reference across 240 deterministic randomized cases.
5. **Native verification.** Requires authorized tenant execution and independently
   captured assertions. The current reports identify all results as offline
   reference replay. Native KQL and YARA-L semantics are outside this release.

## Execution boundaries

Stages use exact predicates, a strict event-time order, a common join value and
one bounded window. The evaluator sorts and deduplicates inputs, then retains the
latest feasible start per key and stage. This is sufficient to decide whether
a later terminal can complete the sequence. Proofs are deterministic even when
there are multiple paths. Readiness is measured on the chosen proof. See
[the specification](SPEC.md) for clock semantics and limits.

The package runs in an offline process. The configured bounds and preflight
validation keep malformed or unexpectedly large suites from being treated as
passing builds. Reports expose event IDs and counters, so production exports
should be minimized and artifacts should inherit the data's access policy.

## Adoption boundary

The useful first deployment is a CI job for a parser or ingestion-policy
repository. A release candidate produces two sanitized exports for each labeled
scenario. The gate can then block a loss in detection or evidence without
access to a production tenant. The bundled benchmark is deliberately small and
does not estimate sector-wide false-positive rates or runtime capacity.
