# Security Policy

## Scope

ChronoTrace processes hostile input by design: disk images, registry hives, and log files
from potentially compromised or adversarial systems. A parser bug is a security bug. We
treat the following as in-scope vulnerabilities:

* Memory-safety or crash bugs reachable from evidence input (DoS via malformed image).
* Path traversal or arbitrary file write triggered by parsing a malicious artefact
  (e.g. a ZIP/PDF/OOXML member name, an LNK target path, a registry value).
* Bypass of the evidence write-guard.
* Bypass or forgery of the chain-of-custody ledger or hash verification.
* Report generation vulnerabilities (HTML/JS injection into HTML/PDF reports, SSRF via
  external template references).
* Plugin sandbox escape.
* Credential/key leakage in logs, reports, or the case directory.

Out of scope: physical attacks, attacks requiring an already-compromised analysis host,
and issues in third-party libraries that we cannot mitigate (report upstream, but tell us
too).

## Reporting a vulnerability

**Do not open a public issue.**

Email `security@chronotrace.example` with:

1. A description of the vulnerability and its impact.
2. Reproduction steps, including a minimal fixture if applicable.
3. Affected versions.
4. Any suggested mitigation.
5. Whether you wish to be credited.

If you need to encrypt, our PGP key fingerprint is published at
`https://chronotrace.example/.well-known/security.txt` and in `SECURITY.txt`.

### What to expect

| Stage | Target |
|---|---|
| Acknowledgement | 2 business days |
| Triage & severity assessment | 5 business days |
| Fix for Critical/High | 30 days |
| Fix for Medium/Low | next minor release |
| Public disclosure | coordinated, default 90 days after fix |

We follow coordinated disclosure. We will credit reporters in the release notes unless
asked otherwise. We do not operate a paid bounty programme at this time.

## Threat model

| Asset | Threat | Mitigation |
|---|---|---|
| Evidence integrity | Accidental or malicious write | Read-only handles; write-guard; hashes recorded at acquisition |
| Evidence integrity | Post-acquisition tampering | SHA-256 manifest + hash-chained custody ledger + optional HMAC |
| Case data confidentiality | Leakage via reports/logs | Redaction profiles; no network egress by default; logs exclude raw PII by default |
| Analysis host | Parser RCE from malicious artefact | Memory-safe parsing where possible; fuzzing; sandboxed plugin runner (`--sandbox`) |
| Report integrity | Tampering with generated report | Merkle root over derived artefacts + report hash in ledger |
| Examiner credentials | Ledger signing key theft | Keys never persisted by the tool; env/KMS/HSM only; zeroized after use |
| Chain of custody | Repudiation | Append-only ledger with monotonic sequence and hash chaining |

## Hardening recommendations for examiners

* Run ChronoTrace as an unprivileged user in a dedicated VM, network-isolated.
* Mount evidence read-only, or better, pass images rather than devices.
* Set `CHRONOTRACE_NO_NETWORK=1` to enforce offline operation.
* Use `--sandbox` for untrusted images (seccomp/nsjail-based plugin isolation on Linux).
* Store the ledger and manifest on WORM media or with an external timestamping service.
* Sign the ledger with an HMAC key held in a KMS/HSM rather than a file.
* Never run the tool against a live production system's writable volume.

## Supported versions

| Version | Supported |
|---|---|
| 1.3.x | ✅ |
| 1.2.x | Security fixes only |
| < 1.2 | ❌ |

## Fuzzing

Continuous fuzzing via OSS-Fuzz style harnesses in `fuzz/`. Corpora are synthetic. To run
locally:

```bash
pip install -e ".[fuzz]"
python -m chronotrace.fuzz.run --target evtx --iterations 100000
````

svgsvg

## Dependency policy

- Dependencies are pinned and audited with `pip-audit` in CI.
- New dependencies require justification and a license compatible with Apache-2.0.
- Native parsers must ship with a fuzzing harness.

text
