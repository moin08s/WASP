# API Reference

ChronoTrace exposes a Python API for automating all six project specification objectives:
file metadata extraction, system artefact extraction, timestamp extraction, chronological
activity timeline reconstruction, SHA-256 evidence integrity, and structured investigation
report generation. The API follows the same provenance, read-only, and determinism rules
as the CLI.

## Case

```python
from chronotrace import Case

case = Case.open("./CASE-2024-0117")

# PS: file metadata extraction + system artefact extraction
case.ingest(profile="windows", jobs=8).run()

# PS: file metadata extraction + system artefact extraction + timestamp extraction
case.extract(plugins="all", jobs=8).run()

# PS: chronological activity timeline reconstruction
case.build_timeline(
    from_="2024-01-01T00:00:00Z",
    to="2024-04-01T00:00:00Z",
)
```

## Timeline

```python
from chronotrace import Timeline

# PS: chronological activity timeline reconstruction
tl = Timeline.from_case(case)
for event in tl.between("2024-03-10T00:00:00Z", "2024-03-12T00:00:00Z"):
    print(event.timestamp_utc, event.action, event.object)
```


Timeline queries can filter by action, confidence, user, host, object type, time range, and source provenance. The SQLite index may also be queried read-only.

## Reporting

```python
from chronotrace.report import ReportBuilder

# PS: structured investigation reports (SHA-256 integrity hashes included by default)
ReportBuilder(case).template("full").formats("html", "json").build()
```


## Event model

The primary event fields are `event_id`, `timestamp_utc`, `timestamp_raw`, `timestamp_type`, `source`, `host`, `user`, `action`, `object`, `confidence`, `evidence`, `tags`, and `raw`.

## Stability

The unified event schema is versioned independently of the application. Breaking changes require a schema-major increment and a migration path; migrations preserve original legacy JSON under `derived/legacy/`.
