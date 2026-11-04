"""Offline regression gate for ordered, identity-linked security signals."""
import argparse
from collections import defaultdict
from hashlib import sha256
import json
from pathlib import Path


def nonempty(value):
    return isinstance(value, str) and bool(value.strip())


def integer(value):
    return type(value) is int and value >= 0


def evaluate(contract, events):
    first, second = contract["sequence"]
    window, deadline = contract["window"], contract["deadline"]
    if not all(map(nonempty, (first, second))) or first == second:
        raise ValueError("Sequence must contain two distinct event kinds")
    if not integer(window) or not integer(deadline):
        raise ValueError("Window and deadline must be nonnegative integer seconds")
    by_id = {}
    for event in events:
        event_id = event["id"]
        if not nonempty(event_id) or not nonempty(event["kind"]):
            raise ValueError("Event IDs and kinds must be nonempty strings")
        if not integer(event["time"]) or not integer(event["arrival"]):
            raise ValueError("Event times must be nonnegative integer seconds")
        if event["arrival"] < event["time"]:
            raise ValueError("Arrival cannot precede event time")
        if event_id in by_id and by_id[event_id] != event:
            raise ValueError(f"Conflicting duplicate ID: {event_id}")
        by_id[event_id] = event

    history = defaultdict(list)
    evidence = []
    issues = defaultdict(list)
    counts = dict.fromkeys((first, second), 0)
    for event in sorted(by_id.values(), key=lambda row: (row["time"], row["id"])):
        kind = event["kind"]
        if kind not in counts:
            continue
        counts[kind] += 1
        if event["arrival"] > deadline:
            issues["late"].append(event["id"])
            continue
        identity = event.get("identity")
        if not nonempty(identity):
            issues["missing_identity"].append(event["id"])
            continue
        if kind == first:
            history[identity].append(event)
        else:
            for prior in reversed(history[identity]):
                delta = event["time"] - prior["time"]
                if delta > window:
                    break
                if delta > 0:
                    evidence.append([prior["id"], event["id"]])
                    break
    for kind, count in counts.items():
        if count == 0:
            issues["absent_kind"].append(kind)
    return {"detected": bool(evidence), "evidence": evidence, "counts": counts,
            "input_count": len(events), "unique_count": len(by_id), "issues": dict(issues)}


def compare(suite):
    contract = suite["contract"]
    results = []
    names = set()
    for case in suite["cases"]:
        name, expected = case["name"], case["expected"]
        if not nonempty(name) or name in names or type(expected) is not bool:
            raise ValueError("Case names must be unique and expected must be boolean")
        names.add(name)
        baseline = evaluate(contract, case["baseline"])
        candidate = evaluate(contract, case["candidate"])
        status = "pass"
        if baseline["detected"] != expected:
            status = "invalid_baseline"
        elif candidate["detected"] != expected:
            status = "missed_detection" if expected else "new_false_positive"
        results.append({"case": name, "expected": expected, "status": status,
                        "baseline": baseline, "candidate": candidate})
    if not results:
        raise ValueError("At least one case is required")
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("suite", type=Path)
    args = parser.parse_args()
    try:
        raw = args.suite.read_bytes()
        cases = compare(json.loads(raw))
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(2, f"Invalid suite: {error}\n")
    print(json.dumps({"version": 1, "suite_sha256": sha256(raw).hexdigest(),
                      "cases": cases}, indent=2))
    return int(any(case["status"] != "pass" for case in cases))


if __name__ == "__main__":
    raise SystemExit(main())
