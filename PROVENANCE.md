# Fixture provenance and reproduction

The SentinelOps fixture was generated offline using `python -m rba` at
`60547c5cdd2c7a5739d56021fbd25ab9cf4671ff`. Its
`dataset.synthetic.json` export supplied 18 records and 17 distinct event IDs.
The source lab additionally merges a logical duplicate with a distinct ID.
Detection Continuity deduplicates on the exported event ID.
The bundled projection retains the synthetic flag, event ID, kind, source,
event time, actor and resource. The negative variant removes diagnostic-change
events. The replay's five stages are a new reference contract for the exported
signals, independent of the lab's own risk score.

The Google SecOps fixture was generated at
`bacd4713ac97adc74339a87e494117975ed9b9e8` using these lab commands:

```sh
secops-lab generate --scenario cross --out var/continuity-input.jsonl
secops-lab normalize var/continuity-input.jsonl > var/continuity-normalized.jsonl
```

The bundled projection keeps the synthetic envelope ID, source, origin and UDM
object. The raw and parsed payloads are omitted. The benign variant changes the
actor to another reserved-domain identity. The candidate regression removes the
IAM actor while retaining both events and their IDs. Those edits are deliberate
test mutations. The ECS-shaped fixture was authored for this project.

The two adapters accept the original export shapes as well as these projections.
Run the following commands from Detection Continuity to validate fresh exports:

```sh
python -m detcontinuity adapt sentinelops-rba /path/to/dataset.synthetic.json
python -m detcontinuity adapt google-secops-lab /path/to/continuity-normalized.jsonl
```

The supplied cases run locally using synthetic data. Reproducing them does not
require Azure credentials, a Google SecOps tenant, an API token or cloud billing.
