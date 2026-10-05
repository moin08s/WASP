"""Configuration management and effective config serialization."""

from __future__ import annotations
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
import tomli_w
from pydantic import BaseModel, Field

try:
    import tomllib
except ImportError:
    import tomli as tomllib  # type: ignore


class GeneralConfig(BaseModel):
    case_id: str = "CASE-DEFAULT"
    examiner: str = "Forensic Examiner"
    organization: str = "DFIR Unit"
    description: str = "Digital Forensics Examination"
    authorization_ref: str = "INTERNAL-001"
    deterministic: bool = True
    strict: bool = False
    no_network: bool = True
    locale: str = "C.UTF-8"


class PathsConfig(BaseModel):
    workdir: str = "./work"
    tmpdir: str = "./tmp"
    evidence_dir: str = "./evidence"
    derived_dir: str = "./derived"
    index_dir: str = "./index"
    report_dir: str = "./reports"
    custody_dir: str = "./custody"


class LoggingConfig(BaseModel):
    level: str = "info"
    format: str = "text"
    file: Optional[str] = None
    scrub_pii: bool = True


class AcquireConfig(BaseModel):
    format: str = "ewf"
    hash: str = "sha256"
    hash_extra: List[str] = Field(default_factory=lambda: ["blake3"])
    segment_size: str = "2G"
    verify: str = "readback"


class CaseConfig(BaseModel):
    general: GeneralConfig = Field(default_factory=GeneralConfig)
    paths: PathsConfig = Field(default_factory=PathsConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    acquire: AcquireConfig = Field(default_factory=AcquireConfig)

    @classmethod
    def load(cls, path: str | Path | None = None) -> "CaseConfig":
        config_data: Dict[str, Any] = {}
        # 1. Global config if exists
        global_path = Path.home() / ".config" / "chronotrace" / "config.toml"
        if global_path.exists():
            with open(global_path, "rb") as f:
                config_data.update(tomllib.load(f))

        # 2. Case or custom path
        if path and Path(path).exists():
            with open(path, "rb") as f:
                custom_data = tomllib.load(f)
                for k, v in custom_data.items():
                    if isinstance(v, dict) and k in config_data:
                        config_data[k].update(v)
                    else:
                        config_data[k] = v

        return cls.model_validate(config_data)

    def save(self, path: str | Path) -> None:
        """Write effective configuration to TOML file."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        dump = self.model_dump(exclude_none=True)
        with open(target, "wb") as f:
            tomli_w.dump(dump, f)
