from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path

from domainwalk.findings import flatten_findings, score

CONFIG_NAME = ".domainwalk.toml"
USER_CONFIG = Path.home() / ".config" / "domainwalk" / "config.toml"


@dataclass
class Config:
    path: Path | None = None
    timeout: float | None = None
    mute: dict[str, str] = field(default_factory=dict)


def find_config(explicit: str | None = None, cwd: Path | None = None) -> Path | None:
    if explicit:
        path = Path(explicit)
        if not path.is_file():
            raise FileNotFoundError(f"no existe el archivo de configuración: {path}")
        return path
    local = (cwd or Path.cwd()) / CONFIG_NAME
    if local.is_file():
        return local
    if USER_CONFIG.is_file():
        return USER_CONFIG
    return None


def load_config(explicit: str | None = None, cwd: Path | None = None) -> Config:
    path = find_config(explicit, cwd)
    if path is None:
        return Config()
    with open(path, "rb") as fh:
        data = tomllib.load(fh)
    mute = {str(k): str(v) for k, v in (data.get("mute") or {}).items()}
    timeout = data.get("timeout")
    return Config(path=path, timeout=float(timeout) if timeout is not None else None, mute=mute)


def mute_reason(finding_id: str, mute: dict[str, str]) -> str | None:
    """Coincidencia exacta o por patrón (hdr.* silencia todas las cabeceras)."""
    if finding_id in mute:
        return mute[finding_id]
    for pattern, reason in mute.items():
        if fnmatch(finding_id, pattern):
            return reason
    return None


def apply_mutes(report: dict, mute: dict[str, str]) -> dict:
    """Baja a info los hallazgos silenciados y recalcula el resumen.

    Se guarda el nivel original para que el diff siga viendo un empeoramiento
    aunque el hallazgo esté silenciado.
    """
    if not mute:
        return report
    muted = 0
    for item in flatten_findings(report):
        if item["level"] in {"ok", "info"}:
            continue
        reason = mute_reason(item["id"], mute)
        if reason is None:
            continue
        item["original_level"] = item["level"]
        item["level"] = "info"
        item["muted"] = True
        item["mute_reason"] = reason
        muted += 1
    if muted:
        report["summary"] = score(flatten_findings(report))
        report["summary"]["muted"] = muted
    return report
