# Plugin Development

ChronoTrace uses versioned Python entry-point plugins so new artefact parsers can be
added without changing the core pipeline. Plugins are the primary mechanism for extending
**file metadata extraction** and **system artefact extraction** coverage — the first two
project specification objectives. Every event a plugin emits also feeds the
**timestamp extraction** and **chronological activity timeline reconstruction** stages.

## Plugin contract

A plugin subclasses `chronotrace.plugin.ArtifactPlugin` and declares:

- `name` and `version`.
- Supported capabilities and input formats/globs.
- Applicable operating systems or filesystem types.
- Whether parallel execution is safe.
- Parser options and schema version.

The core method is conceptually:

```python
parse(source: EvidenceView) -> Iterator[Event]
```

Plugins receive read-only evidence views. They must never write to evidence.

## Registration

Create `chronotrace/plugins/<name>/` containing `__init__.py`, `plugin.py`, and `manifest.toml`, then register the plugin under the `chronotrace.plugins` Python entry-point group.

## Required behaviour

- Preserve source artefact, record ID/offset, evidence ID, and parser version.
- Emit `ParseWarning` records instead of silently dropping malformed records.
- Assign confidence and a rationale when timestamps or fields are inferred.
- Produce deterministic output independent of thread scheduling.
- Validate lengths, offsets, compression limits, and untrusted strings before parsing.

## Testing

Every plugin should include unit tests, malformed-input tests, a public/synthetic fixture with provenance, and deterministic-output tests. Binary parsers should also have a fuzz harness.

## Example manifest

```toml
name = "example_artifact"
version = "1.0.0"
api_version = "2"
capabilities = ["timeline", "metadata"]
parallel_safe = true
applies_to = ["windows"]
```
