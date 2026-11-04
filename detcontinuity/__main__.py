"""Run the gate, a fault benchmark or a laboratory adapter."""

import argparse
import json
from hashlib import sha256
from pathlib import Path

from . import __version__, report
from .adapters import convert
from .inputs import decode, label, path_string, read
from .suite import benchmark, prepare, rule_registry, run


def impact(rules, kind, field):
    if not label(kind) or field is not None and not path_string(field):
        raise ValueError("Invalid kind or field")
    matches = []
    for rule in rules.values():
        for index, stage in enumerate(rule["stages"], 1):
            if stage["kind"] != kind:
                continue
            dependencies = sorted(
                {"id", "kind", "time", "arrival", stage["join"], *stage.get("where", {})}
                | ({"source"} if "source" in stage else set())
            )
            if field is None or any(
                dep == field or dep.startswith(field + ".") for dep in dependencies
            ):
                matches.append({"rule": rule["id"], "stage": index, "fields": dependencies})
    return matches


def main():
    parser = argparse.ArgumentParser(prog="detcontinuity", description=__doc__)
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check", help="Gate a candidate against labeled scenarios")
    check.add_argument("suite", type=Path)
    check.add_argument("--format", choices=["json", "html", "junit"], default="json")
    bench = commands.add_parser("benchmark", help="Measure synthetic fault impact")
    bench.add_argument("suite", type=Path)
    bench.add_argument("faults", type=Path)
    bench.add_argument("--format", choices=["json", "html"], default="json")
    query = commands.add_parser(
        "impact", help="Find rule stages depending on an event kind or field"
    )
    query.add_argument("suite", type=Path)
    query.add_argument("kind")
    query.add_argument("--field")
    adapter = commands.add_parser(
        "adapt", help="Project a synthetic laboratory export to canonical JSON"
    )
    adapter.add_argument("format", choices=["sentinelops-rba", "google-secops-lab", "mapped-jsonl"])
    adapter.add_argument("input", type=Path)
    adapter.add_argument("--mapping", type=Path)
    args = parser.parse_args()
    failed = False
    try:
        if args.command == "adapt":
            if (args.format == "mapped-jsonl") != bool(args.mapping):
                raise ValueError("Only mapped-jsonl accepts and requires a mapping")
            mapping = decode(read(args.mapping)) if args.mapping else None
            result = convert(args.format, read(args.input), mapping=mapping)
            format_name = "json"
        else:
            raw = read(args.suite)
            document = decode(raw)
            result = {
                "report_version": 1,
                "tool_version": __version__,
                "evidence": "offline_reference_replay",
                "suite_sha256": sha256(raw).hexdigest(),
            }
            format_name = getattr(args, "format", "json")
            if args.command == "impact":
                result["dependencies"] = impact(rule_registry(document), args.kind, args.field)
            else:
                rules, cases = prepare(
                    document, args.suite.parent, require_candidate=args.command == "check"
                )
            if args.command == "check":
                result.update(run(rules, cases))
                failed = any(row["status"] != "pass" for row in result["assertions"])
            elif args.command == "benchmark":
                fault_bytes = read(args.faults)
                result["faults_sha256"] = sha256(fault_bytes).hexdigest()
                result["faults"] = benchmark(rules, cases, decode(fault_bytes))
                failed = any(group["summary"].get("invalid_baseline") for group in result["faults"])
        if format_name == "html":
            print(report.html(result), end="")
        elif format_name == "junit":
            print(report.junit(result), end="")
        else:
            print(json.dumps(result, indent=2, allow_nan=False))
    except (OSError, ValueError, KeyError, TypeError, OverflowError, RecursionError):
        # Avoid copying input values, identities or local paths into CI errors.
        parser.exit(
            2, "Invalid or unreadable input. Check the suite schema, limits and adapter format.\n"
        )
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
