#!/usr/bin/env python3
"""Scrape Docker Hub for php:X.Y.Z-apache images and extract
libphp.so symbol offsets -- no docker daemon needed.

For a tag, this fetches the OCI manifest from the Docker
Registry v2 API, downloads the layer that contains
/usr/lib/apache2/modules/libphp.so, and parses its ELF
symtab for zif_system / zval_ptr_dtor (the same parse
docker/offsets.py does against a running container).

Only the two symbol offsets come out of this.  S/hsv and
the stage heap-shaping parameters are build-specific heap
layout, NOT derivable from the ELF -- those still need a
lab calibration run.  So a scraped row is a starting
point: rce_verified=false by definition.

usage:
  python3 tools/registry_scrape.py --tag 8.4.26-apache
  python3 tools/registry_scrape.py --tag 8.5.11-apache --write

writes profiles/php-<ver>-trixie-amd64.json with
rce_verified=false when --write is given.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import struct
import sys
import tarfile
import urllib.request
import urllib.parse

REGISTRY = "https://registry-1.docker.io"
AUTH = "https://auth.docker.io/token"
REPO = "library/php"
LIB_CANDIDATES = (
    "usr/lib/apache2/modules/libphp.so",
    "usr/lib/apache2/modules/libphp7.so",
)

SHT_SYMTAB = 2
SHT_DYNSYM = 11
PT_LOAD = 1


def token() -> str:
    q = urllib.parse.urlencode(
        {"service": "registry.docker.io",
         "scope": "repository:%s:pull" % REPO})
    with urllib.request.urlopen("%s?%s" % (AUTH, q),
                                timeout=30) as r:
        return json.load(r)["token"]


def get(url: str, headers: dict | None = None,
        timeout: float = 120.0) -> bytes:
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def manifest(tag: str, tok: str) -> dict:
    accept = ("application/vnd.docker.distribution.manifest.v2+json,"
              "application/vnd.oci.image.manifest.v1+json,"
              "application/vnd.docker.distribution.manifest.list.v2+json,"
              "application/vnd.oci.image.index.v1+json")
    url = "%s/v2/%s/manifests/%s" % (REGISTRY, REPO, tag)
    data = get(url, {"Authorization": "Bearer %s" % tok,
                     "Accept": accept})
    m = json.loads(data)
    # manifest list / index: pick linux amd64
    if "manifests" in m:
        for sub in m["manifests"]:
            p = sub.get("platform", {})
            if (p.get("os") == "linux"
                    and p.get("architecture") == "amd64"):
                return manifest(sub["digest"], tok)
        raise SystemExit("no linux/amd64 in manifest list")
    return m


def parse_elf(data: bytes) -> tuple[int, dict[str, int]]:
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise SystemExit("libphp.so is not a little-endian ELF64")
    e_phoff, = struct.unpack_from("<Q", data, 0x20)
    e_shoff, = struct.unpack_from("<Q", data, 0x28)
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    e_shentsize, e_shnum = struct.unpack_from("<HH", data, 0x3A)
    loads = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, = struct.unpack_from("<I", data, off)
        p_vaddr, = struct.unpack_from("<Q", data, off + 16)
        p_memsz, = struct.unpack_from("<Q", data, off + 40)
        if p_type == PT_LOAD and p_memsz:
            loads.append(p_vaddr)
    bias = min(loads)
    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, sh_type = struct.unpack_from("<II", data, off)
        sh_offset, sh_size = struct.unpack_from("<QQ", data, off + 24)
        sh_link, = struct.unpack_from("<I", data, off + 40)
        sh_entsize, = struct.unpack_from("<Q", data, off + 56)
        sections.append({"offset": sh_offset, "size": sh_size,
                         "link": sh_link, "entsize": sh_entsize,
                         "type": sh_type})
    wanted = {"zif_system": None, "zval_ptr_dtor": None}
    for sec in sections:
        if sec["type"] not in (SHT_SYMTAB, SHT_DYNSYM):
            continue
        strtab = (sections[sec["link"]]
                  if sec["link"] < len(sections) else None)
        if strtab is None:
            continue
        entsize = sec["entsize"] or 24
        for i in range(sec["size"] // entsize):
            off = sec["offset"] + i * entsize
            st_name, = struct.unpack_from("<I", data, off)
            st_value, = struct.unpack_from("<Q", data, off + 8)
            if st_name == 0:
                continue
            name_off = strtab["offset"] + st_name
            end = data.find(b"\x00", name_off)
            if end < 0:
                continue
            name = data[name_off:end].decode("ascii", "replace")
            if name in wanted and wanted[name] is None:
                wanted[name] = st_value
    missing = [k for k, v in wanted.items() if v is None]
    if missing:
        raise SystemExit("symbols not found: " + ", ".join(missing))
    return bias, wanted





def extract_libphp(m: dict, tok: str) -> bytes:
    """Download layers until the PHP SAPI module is
    found (libphp.so on 8.x, libphp7.so on 7.x)."""
    for layer in m.get("layers", []):
        blob = get("%s/v2/%s/blobs/%s" % (REGISTRY, REPO,
                                            layer["digest"]),
                   {"Authorization": "Bearer %s" % tok})
        try:
            tf = tarfile.open(fileobj=io.BytesIO(blob),
                              mode="r:*")
        except (tarfile.TarError, OSError):
            continue
        member = None
        for cand in LIB_CANDIDATES:
            try:
                member = tf.getmember(cand)
                break
            except KeyError:
                continue
        if member is None:
            tf.close()
            continue
        data = tf.extractfile(member).read()
        tf.close()
        return data
    raise SystemExit("libphp.so / libphp7.so not found "
                     "in any layer")


def php_version_from_config(m: dict, tok: str) -> str:
    cfg = get("%s/v2/%s/blobs/%s" % (REGISTRY, REPO,
                                       m["config"]["digest"]),
              {"Authorization": "Bearer %s" % tok})
    c = json.loads(cfg)
    env = c.get("config", {}).get("Env", [])
    for e in env:
        if e.startswith("PHP_VERSION="):
            return e.split("=", 1)[1]
    return ""


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", required=True,
                    help="image tag, e.g. 8.4.26-apache")
    ap.add_argument("--write", action="store_true",
                    help="write a profiles/ row "
                         "(rce_verified=false)")
    args = ap.parse_args(argv)

    tok = token()
    m = manifest(args.tag, tok)
    ver = php_version_from_config(m, tok)
    data = extract_libphp(m, tok)
    bias, syms = parse_elf(data)
    zif = syms["zif_system"] - bias
    dtor = syms["zval_ptr_dtor"] - bias
    print("tag            %s" % args.tag)
    print("PHP_VERSION    %s" % (ver or "?"))
    print("zif_system     0x%x" % zif)
    print("zval_ptr_dtor  0x%x" % dtor)
    print("note           S/hsv/stage params NOT scraped "
          "(heap layout; needs lab calibration)")

    if args.write and ver:
        prof_dir = os.path.join(
            os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))),
            "profiles")
        os.makedirs(prof_dir, exist_ok=True)
        distro = "trixie" if "trixie" in json.dumps(
            m.get("annotations", {})) else "unknown"
        name = "php-%s-%s-amd64" % (ver, distro)
        prof = {
            "name": name,
            "php_version": ver,
            "distro": distro,
            "arch": "amd64",
            "image": "php:%s" % args.tag,
            "offsets": {
                "zif_system": "0x%x" % zif,
                "zval_ptr_dtor": "0x%x" % dtor,
                "S": "0xF8398",
                "hsv": "0x7D720",
            },
            "rce_verified": False,
            "notes": ("symbol offsets scraped from the "
                      "official image via the registry API; "
                      "S/hsv are legacy 8.4.26 placeholders "
                      "and stage params are unset -- "
                      "calibrate before use"),
        }
        path = os.path.join(prof_dir, name + ".json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(prof, f, indent=2)
            f.write("\n")
        print("profile        %s (rce_verified=false)" % path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
