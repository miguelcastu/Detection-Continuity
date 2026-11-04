"""Evaluate ordered, bounded sequences grouped by an explicit join key."""

from collections import Counter, defaultdict
from itertools import groupby

from .inputs import (
    MISSING,
    event_list,
    fingerprint,
    keys,
    label,
    locate,
    path_string,
    scalar,
    seconds,
)


def validate_rule(rule):
    keys(rule, ("id", "stages", "window"), ("description",))
    if not label(rule["id"]) or not seconds(rule["window"]):
        raise ValueError("Invalid rule ID or window")
    if "description" in rule and not label(rule["description"]):
        raise ValueError("Invalid rule description")
    if not isinstance(rule["stages"], list) or not 1 <= len(rule["stages"]) <= 8:
        raise ValueError("A rule requires one to eight stages")
    for stage in rule["stages"]:
        keys(stage, ("kind", "join"), ("source", "where"))
        if not label(stage["kind"]) or "source" in stage and not label(stage["source"]):
            raise ValueError("Invalid stage kind or source")
        if not path_string(stage["join"]):
            raise ValueError("Invalid join field path")
        filters = stage.get("where", {})
        if not isinstance(filters, dict) or len(filters) > 32:
            raise ValueError("Expected up to 32 field predicates")
        if not all(path_string(path) and scalar(value) for path, value in filters.items()):
            raise ValueError("Predicates require a field path and scalar JSON value")


def same_scalar(left, right):
    return type(left) is type(right) and left == right


def reject(counts, examples, reason, event_id):
    counts[reason] += 1
    if len(examples[reason]) < 5:
        examples[reason].append(event_id)


def replay(rule, records, deadline):
    return replay_validated(rule, event_list(records), deadline)


def replay_validated(rule, events, deadline):
    stages = rule["stages"]
    state = [dict() for _ in stages]
    counters = [Counter() for _ in stages]
    samples = [defaultdict(list) for _ in stages]
    evidence = []
    stages_by_kind = defaultdict(list)
    for i, stage in enumerate(stages):
        stages_by_kind[stage["kind"]].append((i, stage))

    # Read only state from earlier timestamps. Update the frontier after the
    # whole bucket so tied events never form an ordered chain.
    for timestamp, bucket in groupby(events, key=lambda event: event["time"]):
        pending = {}
        for event in bucket:
            for i, stage in stages_by_kind[event["kind"]]:
                if "source" in stage and event.get("source") != stage["source"]:
                    continue
                counts = counters[i]
                counts["seen"] += 1
                if event["arrival"] > deadline:
                    reject(counts, samples[i], "late", event["id"])
                    continue
                values = [
                    (locate(event, path), expected)
                    for path, expected in stage.get("where", {}).items()
                ]
                if any(value is MISSING for value, _ in values):
                    reject(counts, samples[i], "missing_predicate", event["id"])
                    continue
                if any(not same_scalar(value, expected) for value, expected in values):
                    reject(counts, samples[i], "predicate_mismatch", event["id"])
                    continue
                join = locate(event, stage["join"])
                if not label(join):
                    reject(counts, samples[i], "missing_join", event["id"])
                    continue
                counts["eligible"] += 1
                if i:
                    previous = state[i - 1].get(join)
                    if previous is None or timestamp - previous[0]["time"] > rule["window"]:
                        reject(counts, samples[i], "no_preceding_stage", event["id"])
                        continue
                    chain = (*previous, event)
                else:
                    chain = (event,)
                if i == len(stages) - 1:
                    ready = max(item["arrival"] for item in chain)
                    evidence.append(
                        {
                            "ids": [item["id"] for item in chain],
                            "ready": ready,
                            "lag": ready - timestamp,
                            "terminal": event["id"],
                        }
                    )
                    continue
                key = (i, join)
                # Latest start dominates for future existence within the window.
                existing = pending.get(key)
                if existing is None or chain[0]["time"] > existing[0]["time"]:
                    pending[key] = chain
        for (i, join), chain in pending.items():
            existing = state[i].get(join)
            if existing is None or chain[0]["time"] >= existing[0]["time"]:
                state[i][join] = chain

    return {
        "detected": bool(evidence),
        "matches": evidence,
        "stages": [dict(c) for c in counters],
        "stage_samples": [dict(s) for s in samples],
        "unique_events": len(events),
        "events_sha256": fingerprint(events),
    }
