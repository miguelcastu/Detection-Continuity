"""Run labeled regressions and evaluate change impact under controlled faults."""

from collections import Counter
from copy import deepcopy

from .engine import replay_validated, validate_rule
from .inputs import event_list, fingerprint, keys, label, load_events, path_string, seconds


def expectation(value):
    keys(value, ("detected",), ("terminals", "max_lag"))
    if type(value["detected"]) is not bool:
        raise ValueError("Expected detected to be a boolean")
    if not value["detected"] and len(value) > 1:
        raise ValueError("Evidence constraints require a positive expectation")
    if "terminals" in value:
        ids = value["terminals"]
        if (
            not isinstance(ids, list)
            or not ids
            or not all(map(label, ids))
            or len(set(ids)) != len(ids)
        ):
            raise ValueError("Expected a nonempty list of distinct terminal IDs")
    if "max_lag" in value and not seconds(value["max_lag"]):
        raise ValueError("Invalid maximum lag")


def violations(expected, result):
    if expected["detected"] != result["detected"]:
        return ["missed_detection" if expected["detected"] else "new_false_positive"]
    reasons = []
    if "terminals" in expected and set(expected["terminals"]) != {
        match["terminal"] for match in result["matches"]
    }:
        reasons.append("terminal_evidence_changed")
    if "max_lag" in expected and any(
        match["lag"] > expected["max_lag"] for match in result["matches"]
    ):
        reasons.append("lag_budget_exceeded")
    return reasons


def rule_registry(document):
    keys(document, ("schema_version", "rules", "cases"))
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise ValueError("Unsupported suite schema version")
    rules = {}
    if not isinstance(document["rules"], list) or not 1 <= len(document["rules"]) <= 64:
        raise ValueError("A suite requires one to 64 rules")
    for rule in document["rules"]:
        validate_rule(rule)
        if rule["id"] in rules:
            raise ValueError("Duplicate rule ID")
        rules[rule["id"]] = rule
    return rules


def prepare(document, root, *, require_candidate):
    rules = rule_registry(document)
    if not isinstance(document["cases"], list) or not 1 <= len(document["cases"]) <= 128:
        raise ValueError("A suite requires one to 128 cases")
    names = set()
    labels = {rule_id: set() for rule_id in rules}
    prepared = []
    total = 0
    workload = 0
    for case in document["cases"]:
        keys(case, ("name", "deadline", "baseline", "expect"), ("candidate",))
        if not label(case["name"]) or case["name"] in names or not seconds(case["deadline"]):
            raise ValueError("Invalid or duplicate case name, or invalid deadline")
        names.add(case["name"])
        expected = case["expect"]
        if not isinstance(expected, dict) or not expected or not expected.keys() <= rules.keys():
            raise ValueError("Case expectations must reference registered rules")
        for rule_id, value in expected.items():
            expectation(value)
            labels[rule_id].add(value["detected"])
        if require_candidate and "candidate" not in case:
            raise ValueError("A check requires a candidate for each case")
        baseline = event_list(load_events(root, case["baseline"]))
        candidate = (
            event_list(load_events(root, case["candidate"])) if require_candidate else baseline
        )
        total += len(baseline) + len(candidate)
        workload += (len(baseline) + len(candidate)) * len(expected)
        if total > 200_000:
            raise ValueError("Suite exceeds 200,000 materialized events")
        if workload > 500_000:
            raise ValueError("Suite exceeds 500,000 event/rule evaluations")
        prepared.append(dict(case, baseline=baseline, candidate=candidate))
    if any(values != {False, True} for values in labels.values()):
        raise ValueError("Each rule requires a positive and a negative expectation")
    return rules, prepared


def run(rules, cases):
    rows = []
    for case in cases:
        for rule_id, expected in sorted(case["expect"].items()):
            rule = rules[rule_id]
            baseline = replay_validated(rule, case["baseline"], case["deadline"])
            candidate = replay_validated(rule, case["candidate"], case["deadline"])
            base_errors = violations(expected, baseline)
            errors = violations(expected, candidate)
            status = "invalid_baseline" if base_errors else "regression" if errors else "pass"
            rows.append(
                {
                    "case": case["name"],
                    "rule": rule_id,
                    "status": status,
                    "rule_sha256": fingerprint(rule),
                    "deadline": case["deadline"],
                    "expected": expected,
                    "baseline_violations": base_errors,
                    "candidate_violations": errors,
                    "baseline": baseline,
                    "candidate": candidate,
                }
            )
    summary = dict(Counter(row["status"] for row in rows))
    return {"summary": summary, "assertions": rows}


def mutate(events, fault):
    keys(fault, ("name", "operation", "kind"), ("field", "seconds", "value", "every"))
    if not label(fault["name"]) or not label(fault["kind"]):
        raise ValueError("Invalid fault name or event kind")
    operation = fault["operation"]
    expected = {
        "drop_kind": set(),
        "drop_field": {"field"},
        "delay": {"seconds"},
        "replace_field": {"field", "value"},
        "sample": {"every"},
    }
    if (
        not isinstance(operation, str)
        or operation not in expected
        or (fault.keys() - {"name", "operation", "kind"} != expected[operation])
    ):
        raise ValueError("Invalid fault operation or parameters")
    if "field" in fault:
        field = fault["field"]
        if not path_string(field) or not (field == "identity" or field.startswith("fields.")):
            raise ValueError("Fault field must be identity or nested under fields")
    if operation == "replace_field" and not label(fault["value"]):
        raise ValueError("Replacement must be a nonempty string")
    if operation == "delay" and (not seconds(fault["seconds"]) or fault["seconds"] == 0):
        raise ValueError("Delay must be a positive integer")
    if operation == "sample" and (not seconds(fault["every"]) or fault["every"] < 2):
        raise ValueError("Sampling interval must be at least two")
    result = []
    affected = selected = 0
    for original in events:
        if original["kind"] != fault["kind"]:
            result.append(original)
            continue
        selected += 1
        if operation == "drop_kind" or operation == "sample" and (selected - 1) % fault["every"]:
            affected += 1
            continue
        if operation == "delay":
            event = dict(original, arrival=original["arrival"] + fault["seconds"])
        elif operation in {"drop_field", "replace_field"}:
            event = deepcopy(original)
            *parents, leaf = fault["field"].split(".")
            target = event
            for parent in parents:
                target = target.get(parent) if isinstance(target, dict) else None
            if isinstance(target, dict) and leaf in target:
                if operation == "drop_field":
                    del target[leaf]
                else:
                    target[leaf] = fault["value"]
        else:
            event = original
        affected += event != original
        result.append(event)
    return event_list(result), affected


def benchmark(rules, cases, faults):
    if not isinstance(faults, list) or not 1 <= len(faults) <= 32:
        raise ValueError("Expected one to 32 benchmark faults")
    workload = 2 * len(faults) * sum(len(case["baseline"]) * len(case["expect"]) for case in cases)
    if workload > 500_000:
        raise ValueError("Benchmark exceeds 500,000 event/rule evaluations")
    names = set()
    results = []
    for fault in faults:
        affected = 0
        changed = []
        for case in cases:
            candidate, count = mutate(case["baseline"], fault)
            affected += count
            changed.append(dict(case, candidate=candidate))
        if fault["name"] in names or affected == 0:
            raise ValueError(
                "Benchmark faults must have unique names and change at least one event"
            )
        names.add(fault["name"])
        report = run(rules, changed)
        metrics = Counter()
        for row in report["assertions"]:
            if row["status"] == "invalid_baseline":
                metrics["invalid_baseline"] += 1
                continue
            actual, expected = row["candidate"]["detected"], row["expected"]["detected"]
            metrics[("tp" if actual else "fn") if expected else ("fp" if actual else "tn")] += 1
        results.append(
            {"fault": fault, "affected_events": affected, "metrics": dict(metrics), **report}
        )
    return results
