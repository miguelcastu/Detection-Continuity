# Release verification

| Verification | Result |
| --- | --- |
| Python 3.12.14 tests on Windows | 14 passed from an extracted release archive |
| Sequence engine against exhaustive reference | 240 deterministic randomized comparisons |
| Ruff on the new package and integration tests | Pass |
| Original lab exports | SentinelOps RBA dataset and Google SecOps Lab normalize JSONL imported successfully |
| Healthy suite | Four assertions pass across two rule contracts |
| Candidate parser drift | Three passes and one missed detection with unchanged event volume, exit 1 |
| Mapped JSONL | Positive and negative cases pass with independent event and arrival clocks |
| Fault benchmark | Six independent faults, each exposed by one assertion |
| Distribution | Wheel built from extracted source and installed into a clean virtual environment |
| Installed CLI | Healthy check exits 0 and parser drift check exits 1 when invoked outside the source directory |

The [benchmark report](reports/benchmark.html) is generated from the included
fixtures. It demonstrates missed detections, a new false alert, increased lag
and lost terminal evidence. The [JSON report](reports/benchmark.json) records
rule and event fingerprints and the observed failure reason for each assertion.

The GitHub Actions matrix is included in the source archive. The verification
above was performed locally. Native SIEM execution and production pipeline
validation require separate evidence.
