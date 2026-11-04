"""Bounded JSON inputs and deterministic fingerprints."""

import json
import re
from hashlib import sha256
from pathlib import Path

MAX_BYTES = 32 * 1024 * 1024
MAX_EVENTS = 50_000
PATH = re.compile(r"[@A-Za-z_][@A-Za-z0-9_-]*(?:\.[@A-Za-z_][@A-Za-z0-9_-]*)*")
MISSING = object()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON object key")
        result[key] = value
    return result


def reject_constant(_):
    raise ValueError("Non-finite JSON number")


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique_object, parse_constant=reject_constant)


def read(path):
    with Path(path).open("rb") as file:
        raw = file.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("Input exceeds 32 MiB")
    return raw


def fingerprint(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return sha256(encoded.encode()).hexdigest()


def locate(record, path):
    for part in path.split("."):
        if not isinstance(record, dict) or part not in record:
            return MISSING
        record = record[part]
    return record


def path_string(value):
    return isinstance(value, str) and len(value) <= 240 and PATH.fullmatch(value)


def label(value):
    return (
        isinstance(value, str)
        and bool(value.strip())
        and len(value) <= 256
        and all(
            ord(char) >= 32 and not 0xD800 <= ord(char) <= 0xDFFF and char not in "\ufffe\uffff"
            for char in value
        )
    )


def seconds(value):
    return type(value) is int and 0 <= value < 2**53


def scalar(value):
    return type(value) in (str, int, bool) or value is None


def keys(record, required, optional=()):
    if not isinstance(record, dict):
        raise ValueError("Expected a JSON object")
    if not set(required) <= record.keys() or not record.keys() <= set(required) | set(optional):
        raise ValueError("Missing required or unknown object keys")


def event_list(value):
    if not isinstance(value, list) or len(value) > MAX_EVENTS:
        raise ValueError("Expected a list of at most 50,000 events")
    seen = {}
    for event in value:
        keys(event, ("id", "kind", "time", "arrival"), ("source", "identity", "fields"))
        if not all(label(event[field]) for field in ("id", "kind")):
            raise ValueError("Event ID and kind must be nonempty strings")
        if "source" in event and not label(event["source"]):
            raise ValueError("Invalid event source")
        if not seconds(event["time"]) or not seconds(event["arrival"]):
            raise ValueError("Event times must be nonnegative integer seconds")
        if event["arrival"] < event["time"]:
            raise ValueError("Arrival precedes event time")
        if "fields" in event and not isinstance(event["fields"], dict):
            raise ValueError("Event fields must be an object")
        # Canonical serialization distinguishes JSON booleans from integers.
        event_id = event["id"]
        digest = fingerprint(event)
        if event_id in seen and seen[event_id][0] != digest:
            raise ValueError("Conflicting duplicate event ID")
        seen[event_id] = (digest, event)
    return sorted((event for _, event in seen.values()), key=lambda row: (row["time"], row["id"]))


def relative_file(root, filename):
    if not isinstance(filename, str) or Path(filename).is_absolute():
        raise ValueError("Event file must be relative to the suite")
    path = (root / filename).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ValueError("Event file must stay inside the suite directory")
    return path


def load_events(root, value):
    if isinstance(value, list):
        return value
    keys(value, ("file",), ("format", "mapping"))
    raw = read(relative_file(root, value["file"]))
    format_name = value.get("format", "canonical")
    if (format_name == "mapped-jsonl") != ("mapping" in value):
        raise ValueError("Only mapped-jsonl accepts and requires a mapping")
    if format_name == "canonical":
        return decode(raw)
    from .adapters import convert

    return convert(format_name, raw, mapping=value.get("mapping"))
