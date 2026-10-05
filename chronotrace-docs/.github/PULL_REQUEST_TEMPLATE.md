<!--
Thanks for contributing to ChronoTrace. Please complete every section.
Forensic software has a high correctness bar; incomplete PRs will be sent back.
-->

## Summary

<!-- One paragraph: what does this change and why? -->

## Type of change

- [ ] Bug fix (non-breaking)
- [ ] New feature (non-breaking)
- [ ] Breaking change (schema, CLI, or output format)
- [ ] New artefact plugin
- [ ] Documentation only
- [ ] Refactor / internal (no output change)
- [ ] Security fix

## Related issues

Closes #

## Forensic impact assessment

**Does this change alter tool output?**

- [ ] No — output is byte-identical (explain how you verified)
- [ ] Yes — describe the change and whether it is schema-breaking

**Does this change touch evidence handling?**

- [ ] No
- [ ] Yes — describe how the write-guard and read-only guarantees are preserved

**Does this change affect determinism?**

- [ ] No
- [ ] Yes — explain and justify

**Does this change affect confidence scores or provenance?**

- [ ] No
- [ ] Yes — describe

## Implementation notes

<!-- Key design decisions, alternatives considered, tradeoffs. -->

## Testing

- [ ] Unit tests added/updated
- [ ] Integration test added/updated
- [ ] Fixture added with `PROVENANCE.md`
- [ ] Fuzz harness added (for new binary parsers)
- [ ] Manually verified against a reference implementation / spec (describe below)

### How to reproduce

```bash
chronotrace ...
````

svgsvg

### Evidence of correctness

\<!-- Screenshots, diff of timeline output, spec citations, reference tool output. -->

## Checklist

- □ 

  `pytest -q` passes locally
- □ 

  `ruff check` and `ruff format --check` pass
- □ 

  `mypy --strict chronotrace` passes
- □ 

  `bandit -r chronotrace` clean
- □ 

  `CHANGELOG.md` updated under `[Unreleased]`
- □ 

  Docs updated in `docs/` (and `README.md` if user-facing)
- □ 

  No real case data, PII, or credentials included
- □ 

  Plugin manifest version bumped (if plugin changed)
- □ 

  `SCHEMA_VERSION` bumped and migration noted (if schema changed)

## Reviewer notes

\<!-- Anything you want reviewers to focus on. -->

text
