# Detection Continuity

A CI gate for changes to security telemetry. Replay labeled attack and benign
scenarios against baseline and candidate pipeline outputs. Detect missed alerts,
new false alerts, lost evidence and excessive delivery lag.

## Try a real regression

Run from this directory with Python 3.12 or newer.

```sh
python -m detcontinuity check examples/lab-healthy.json
python -m detcontinuity check examples/lab-regression.json
```

The first command passes four assertions across two laboratories. The second
exits **1**. The same two Google audit events arrive, but a parser revision
removes the IAM actor and breaks the join. The result identifies the affected
rule, stage and missing join count. The baseline match contains the two source
event IDs.

## Measure change impact

```sh
python -m detcontinuity benchmark examples/lab-healthy.json examples/faults.json
python -m detcontinuity impact examples/lab-healthy.json RESOURCE_PERMISSIONS_CHANGE --field fields.actor
python -m detcontinuity check examples/lab-healthy.json --format junit
```

Six injected faults demonstrate three misses, a new false alert, a lag budget
violation and a change in terminal evidence. The latter two preserve binary
detection counts. [Benchmark report](reports/benchmark.html) · [JSON evidence](reports/benchmark.json)

## Use with your pipeline

1. Export the baseline and proposed telemetry for the same scenarios.
2. Map required fields to the replay envelope or supply canonical JSON. The
   [ECS-shaped example](examples/mapped-ecs.json) uses ordinary JSONL and a field
   mapping, including independent event and arrival clocks.
3. Write a rule with one to eight stages. Give it at least one positive and one
   negative case. Add exact terminal IDs and a lag budget where the requirements
   call for them.
4. Run `check` in CI. Publish its JSON, HTML or JUnit output as an artifact.
   Exit **0** passes, **1** blocks the change, and **2** indicates invalid input.

```sh
python -m pip install .
detcontinuity check examples/mapped-ecs.json
python -m unittest -v
```

The CLI has zero runtime dependencies. See [contract and input specification](SPEC.md),
[design and evidence limits](DESIGN.md), [fixture provenance](PROVENANCE.md) and
[release verification](VALIDATION.md).
The original single-rule prototype remains available as `continuity.py`.
