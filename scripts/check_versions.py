#!/usr/bin/env python3
"""Comprueba que la version del motor y del cliente coincide en los 5 sitios donde aparece.

Solo biblioteca estandar (tomllib exige Python >= 3.11). Sale con 1 si hay desajuste.
"""
from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _regex(path: Path, pattern: str) -> str:
    m = re.search(pattern, path.read_text(encoding="utf-8"), re.MULTILINE)
    if not m:
        raise SystemExit(f"ERROR: no se encontro {pattern!r} en {path}")
    return m.group(1)


def collect() -> dict[str, str]:
    root = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    client = tomllib.loads((ROOT / "client" / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    pins = [d for d in root.get("dependencies", []) if re.match(r"lybra-client\b", d)]
    if len(pins) != 1:
        raise SystemExit(f"ERROR: se esperaba una dependencia lybra-client, hay {pins}")
    pin = re.fullmatch(r"lybra-client\s*==\s*(\S+)", pins[0].strip())
    if not pin:
        raise SystemExit(f"ERROR: la dependencia no esta fijada con ==: {pins[0]!r}")
    return {
        "pyproject.toml [project].version": root["version"],
        "pyproject.toml dependency lybra-client==": pin.group(1),
        "client/pyproject.toml [project].version": client["version"],
        "client/src/lybra_client/__init__.py __version__": _regex(
            ROOT / "client" / "src" / "lybra_client" / "__init__.py",
            r"^__version__\s*=\s*[\"']([^\"']+)[\"']",
        ),
        "src/lybra/app/service.py ENGINE_VERSION": _regex(
            ROOT / "src" / "lybra" / "app" / "service.py",
            r"^ENGINE_VERSION\s*=\s*[\"']([^\"']+)[\"']",
        ),
    }


def main() -> int:
    found = collect()
    width = max(len(k) for k in found)
    for where, version in found.items():
        print(f"{where:<{width}}  {version}")
    if len(set(found.values())) != 1:
        print("\nERROR: las versiones no coinciden; actualiza los 5 sitios a la vez.", file=sys.stderr)
        return 1
    print(f"\nOK: todas las versiones son {next(iter(found.values()))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
