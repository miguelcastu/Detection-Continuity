"""Static reports suitable for offline review and CI artifacts."""

from html import escape
from xml.etree.ElementTree import Element, SubElement, tostring


def verdict(row):
    return (
        ", ".join(row["baseline_violations"] or row["candidate_violations"])
        or "All expectations met"
    )


def diagnostic(row):
    if row["status"] == "pass":
        return ""
    side = "baseline" if row["status"] == "invalid_baseline" else "candidate"
    findings = []
    for index, stage in enumerate(row[side]["stages"], 1):
        details = [
            f"{count} {reason.replace('_', ' ')}"
            for reason, count in stage.items()
            if reason not in {"seen", "eligible"}
        ]
        if not stage.get("seen"):
            details.append("no matching event kind/source")
        if details:
            findings.append(f"Stage {index}: " + ", ".join(details))
    return " · ".join(findings)


def html(document):
    cells = []
    groups = document.get("faults") or [document]
    for group in groups:
        fault = group.get("fault", {}).get("name", "Candidate")
        for row in group["assertions"]:
            values = [
                fault,
                row["case"],
                row["rule"],
                row["status"],
                verdict(row),
                diagnostic(row),
                str(len(row["baseline"]["matches"])),
                str(len(row["candidate"]["matches"])),
            ]
            cells.append(
                "<tr>" + "".join(f"<td>{escape(value)}</td>" for value in values) + "</tr>"
            )
    headings = [
        "Change",
        "Scenario",
        "Rule",
        "Status",
        "Finding",
        "Stage observations",
        "Baseline matches",
        "Candidate matches",
    ]
    header = "".join(f'<th scope="col">{name}</th>' for name in headings)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Detection Continuity report</title>
<style>
:root{{color-scheme:light dark}} body{{font:1rem system-ui;max-width:80rem;margin:2rem auto;padding:0 1rem}}
.table{{overflow:auto}} table{{border-collapse:collapse;width:100%}} th,td{{text-align:left;
padding:.6rem;border:1px solid GrayText}} code{{overflow-wrap:anywhere}}
</style></head><body>
<h1>Detection Continuity</h1>
<p>Offline reference replay. See the JSON report for event IDs, stage diagnostics and input fingerprints.</p>
<p>Suite SHA-256 <code>{escape(document["suite_sha256"])}</code></p>
<div class="table"><table><caption>Scenario assertions</caption><thead><tr>{header}</tr></thead>
<tbody>{"".join(cells)}</tbody></table></div></body></html>
"""


def junit(document):
    rows = document["assertions"]
    suite = Element(
        "testsuite",
        name="Detection Continuity",
        tests=str(len(rows)),
        failures=str(sum(row["status"] != "pass" for row in rows)),
    )
    for row in rows:
        case = SubElement(suite, "testcase", classname=row["rule"], name=row["case"])
        if row["status"] != "pass":
            failure = SubElement(case, "failure", message=row["status"])
            failure.text = verdict(row)
    return tostring(suite, encoding="unicode") + "\n"
