"""Project supported synthetic laboratory exports onto the replay envelope."""

from datetime import UTC, datetime
from itertools import islice

from .inputs import MAX_EVENTS, MISSING, decode, event_list, keys, label, locate, path_string


def instant(value):
    if not isinstance(value, str) or "T" not in value:
        raise ValueError("Expected a timezone-aware event timestamp")
    date = datetime.fromisoformat(value)
    if date.utcoffset() is None:
        raise ValueError("Expected a timezone-aware event timestamp")
    elapsed = date.astimezone(UTC) - datetime(1970, 1, 1, tzinfo=UTC)
    return elapsed.days * 86400 + elapsed.seconds


def envelope(event_id, kind, source, time, fields):
    return {
        "id": event_id,
        "kind": kind,
        "source": source,
        "time": time,
        "arrival": time,
        "fields": {key: value for key, value in fields.items() if label(value)},
    }


def sentinel(raw):
    document = decode(raw)
    if not isinstance(document, dict) or document.get("evidence") != "synthetic":
        raise ValueError("Expected the SentinelOps synthetic RBA dataset")
    events = document["events"]
    if not isinstance(events, list):
        raise ValueError("Expected SentinelOps events")
    for event in events:
        if not isinstance(event, dict) or event.get("synthetic") is not True:
            raise ValueError("SentinelOps event must be marked synthetic")
        yield envelope(
            event["event_id"],
            event["kind"],
            event["source"],
            instant(event["time"]),
            {"actor": event.get("actor"), "resource": event.get("resource")},
        )


def google(raw):
    for line in raw.splitlines():
        if not line.strip():
            continue
        event = decode(line)
        if not isinstance(event, dict) or event.get("origin") != "synthetic":
            raise ValueError("Expected Google SecOps Lab synthetic normalize output")
        udm = event["udm"]
        yield envelope(
            event["id"],
            locate(udm, "metadata.eventType"),
            event["source"],
            instant(locate(udm, "metadata.eventTimestamp")),
            {
                "actor": locate(udm, "principal.user.userid"),
                "target_user": locate(udm, "target.user.userid"),
                "resource": locate(udm, "target.resource.name"),
                "operation": locate(udm, "metadata.productEventType"),
            },
        )


def mapped_jsonl(raw, mapping):
    keys(mapping, ("id", "kind", "time", "arrival"), ("source", "identity", "fields", "clock"))
    clock = mapping.get("clock", "rfc3339")
    if clock not in ("rfc3339", "unix-seconds"):
        raise ValueError("Unsupported input clock")
    fields = mapping.get("fields", {})
    if not isinstance(fields, dict) or len(fields) > 32:
        raise ValueError("Expected at most 32 mapped fields")
    for name, path in fields.items():
        if not path_string(name) or "." in name or not path_string(path):
            raise ValueError("Expected a field alias and a source path")
    base_paths = {key: path for key, path in mapping.items() if key not in {"clock", "fields"}}
    if not all(map(path_string, base_paths.values())):
        raise ValueError("Invalid field mapping")
    for line in raw.splitlines():
        if not line.strip():
            continue
        item = decode(line)
        if not isinstance(item, dict):
            raise ValueError("Expected a JSON object on each line")
        projected = {key: locate(item, path) for key, path in base_paths.items()}
        if any(projected[key] is MISSING for key in ("id", "kind", "time", "arrival")):
            raise ValueError("Missing required mapped field")
        if clock == "rfc3339":
            for key in ("time", "arrival"):
                projected[key] = instant(projected[key])
        projected = {key: value for key, value in projected.items() if value is not MISSING}
        projected["fields"] = {
            name: value
            for name, path in fields.items()
            if (value := locate(item, path)) is not MISSING
        }
        yield projected


def convert(format_name, raw, *, mapping=None):
    if format_name == "sentinelops-rba":
        projected = sentinel(raw)
    elif format_name == "google-secops-lab":
        projected = google(raw)
    elif format_name == "mapped-jsonl":
        projected = mapped_jsonl(raw, mapping)
    else:
        raise ValueError("Unsupported input format")
    return event_list(list(islice(projected, MAX_EVENTS + 1)))
