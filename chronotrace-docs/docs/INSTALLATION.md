# Installation

## 1. Requirements

| Component | Minimum | Recommended |
|---|---|---|
| Python | 3.11 | 3.12 |
| OS | Linux (glibc 2.31+), macOS 12+, Windows 10 (WSL2 recommended) | Ubuntu 22.04 LTS |
| RAM | 4 GB | 16 GB+ |
| Disk | 2 GB for the tool | Evidence size × 2.2 for working space |
| CPU | 2 cores | 8+ cores |

> **Windows note:** native Windows is supported for analysis of directory trees and
> images, but several native parsers (`libewf`, `libtsk`, `libesedb`) are more reliable
> under WSL2 or in the provided container. Mounting live Windows volumes is **not**
> supported — always acquire first.

## 2. System dependencies

### Debian / Ubuntu

```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential pkg-config \
  libewf-dev libtsk-dev libvhdi-dev libvmdk-dev libqcow-dev \
  libesedb-dev libregf-dev libfsntfs-dev libbde-dev \
  libssl-dev libffi-dev zlib1g-dev \
  libpango-1.0-0 libcairo2 libgdk-pixbuf-2.0-0  # WeasyPrint (PDF)
````

svgsvg

### Fedora / RHEL

bash

```
sudo dnf install -y \
  gcc gcc-c++ make pkgconf-pkg-config \
  libewf-devel libtsk-devel libvhdi-devel libvmdk-devel libqcow-devel \
  libesedb-devel libregf-devel libfsntfs-devel libbde-devel \
  openssl-devel libffi-devel zlib-devel \
  pango cairo gdk-pixbuf2
```

svgsvg

### macOS (Homebrew)

bash

```
brew install libewf sleuthkit libvhdi libvmdk libqcow libesedb libregf \
             libfsntfs libbde openssl pkg-config pango cairo gdk-pixbuf
export LDFLAGS="-L$(brew --prefix openssl)/lib"
export CPPFLAGS="-I$(brew --prefix openssl)/include"
```

svgsvg

## 3. Install the tool

### pipx (recommended for examiners)

bash

```
pipx install chronotrace
chronotrace doctor
```

svgsvg

### pip (into a virtual environment)

bash

```
python -m venv .venv
source .venv/bin/activate
pip install chronotrace
```

svgsvg

### From source (development)

bash

```
git clone https://github.com/chronotrace/chronotrace.git
cd chronotrace
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,test,docs]"
pre-commit install
pytest -q
```

svgsvg

### Optional extras

| **Extra**   | **Adds**                                                  |
| :---------- | :-------------------------------------------------------- |
| `[pdf]`     | WeasyPrint PDF reporting                                  |
| `[sandbox]` | `nsjail`/`seccomp` plugin isolation (Linux only)          |
| `[fuzz]`    | Fuzzing harnesses                                         |
| `[gpu]`     | Experimental embedding-based clustering of similar events |
| `[cloud]`   | S3/Azure/GCS evidence source adapters                     |
| `[dev]`     | Linters, type checkers, pre-commit                        |
| `[test]`    | pytest, hypothesis, coverage                              |
| `[docs]`    | mkdocs-material                                           |

## 4. Container

bash

```
docker pull ghcr.io/chronotrace/chronotrace:1.3.0

docker run --rm -it \
  --read-only \
  -v /cases/CASE-2024-0117:/case \
  -v /evidence:/evidence:ro \
  --network none \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  ghcr.io/chronotrace/chronotrace:1.3.0 \
  timeline --case /case --format parquet
```

svgsvg

The image runs as UID/GID 10001 (non-root) and is distroless-based. There is no shell in
the default tag; use `:debug` for troubleshooting.

### Docker Compose (batch)

yaml

```
services:
  chronotrace:
    image: ghcr.io/chronotrace/chronotrace:1.3.0
    read_only: true
    network_mode: none
    cap_drop: [ALL]
    security_opt: [no-new-privileges]
    volumes:
      - ./cases:/cases
      - /mnt/evidence:/evidence:ro
    tmpfs:
      - /tmp:size=8g
    command: >
      timeline --case /cases/CASE-2024-0117 --jobs 8 --format parquet
```

svgsvg

## 5. Verification of the installation

bash

```
chronotrace --version
chronotrace doctor            # checks native libs, permissions, tmp space, plugin load
chronotrace plugin list       # lists discovered plugins and versions
```

svgsvg

Expected `doctor` output:

text

```
[ok]   python 3.12.4
[ok]   libewf 20240506
[ok]   libtsk 4.12.1
[ok]   libesedb 20240420
[ok]   write-guard active
[ok]   tmp space 42.1 GiB available
[ok]   34 plugins loaded, 0 failed
[warn] running as root — recommend an unprivileged user
```

svgsvg

## 6. Post-install hardening

bash

```
# Disable all network access at runtime
export CHRONOTRACE_NO_NETWORK=1

# Use a dedicated, unprivileged service account
sudo useradd --system --no-create-home --shell /usr/sbin/nologin chronotrace

# Restrict evidence mounts
sudo mount -o ro,nosuid,nodev,noexec /dev/sdb1 /mnt/evidence
```

svgsvg

## 7. Upgrading

bash

```
pipx upgrade chronotrace
chronotrace doctor
```

svgsvg

Schema migrations run automatically on case open and are recorded in
`case.json.migrations[]`. **Always back up a case directory before upgrading**; migrations
are forward-only.

## 8. Uninstalling

bash

```
pipx uninstall chronotrace
```

svgsvg

Case directories are self-contained and remain readable by the version that created them.
Retain the tool version alongside the case for reproducibility.

## 9. Troubleshooting installation

See [TROUBLESHOOTING.md](https://troubleshooting.md/). Common issues:

| **Symptom**                   | **Fix**                                                                |
| :---------------------------- | :--------------------------------------------------------------------- |
| `ImportError: libewf.so.2`    | Install `libewf-dev`/`libewf`; set `LD_LIBRARY_PATH`                   |
| `pytsk3` build failure        | Install `libtsk-dev` and `pkg-config`                                  |
| PDF report blank pages        | Install Pango/Cairo; `pip install "chronotrace[pdf]"`                  |
| `PermissionError` on evidence | You are not using a read-only mount, or SELinux/AppArmor blocks access |

text
