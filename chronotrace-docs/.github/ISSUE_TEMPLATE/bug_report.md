---
name: Bug report
about: Report incorrect parsing, a crash, or a timeline/report defect
title: "[BUG] "
labels: ["bug", "triage"]
assignees: ""
---

## Summary

<!-- A clear, one-sentence description of the bug. -->

## Impact classification

- [ ] **Critical** — wrong timestamps, missing events, or integrity failure (could affect
      investigative conclusions)
- [ ] **High** — crash or hang on valid input
- [ ] **Medium** — incorrect non-timestamp metadata, report formatting
- [ ] **Low** — cosmetic

## Environment

| Field | Value |
|---|---|
| ChronoTrace version | `chronotrace --version` |
| Python version | |
| OS / kernel | |
| Install method | pip / pipx / container / source |
| Plugin(s) involved | |
| Case config profile | windows / linux / macos / custom |

## Command and configuration

```bash
chronotrace ...
````

svgsvg

toml

```
# relevant config.toml excerpt (redact case-identifying data)
```

svgsvg

## Expected behaviour

\<!-- What did you expect? Cite the spec or reference tool if applicable. -->

## Actual behaviour

\<!-- What happened? Paste the full traceback if applicable. -->

## Evidence source characteristics

| **Field**                            | **Value**                            |
| :----------------------------------- | :----------------------------------- |
| Evidence type                        | raw / E01 / VHDX / directory / other |
| Filesystem                           | NTFS / ext4 / APFS / ...             |
| OS version of the source system      |                                      |
| Approximate artefact size            |                                      |
| Was the artefact carved / recovered? | yes / no / unknown                   |

## Reproducibility

- □ 

  Reproduces on every run
- □ 

  Intermittent
- □ 

  Reproduced once

## Minimal fixture

\<!-- If you can share a synthesized or public-corpus fixture that reproduces the issue, attach it or link it. DO NOT attach real case data or PII. -->

- □ 

  Attached a synthesized fixture
- □ 

  Attached a public-corpus excerpt (source: \_\_\_\_\_\_)
- □ 

  Cannot share a fixture (describe why)

## Additional context

\<!-- Logs with --log-level debug, timeline diff, screenshots, related issues. -->

text
