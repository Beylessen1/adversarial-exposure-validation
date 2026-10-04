import json
import os
import re
import signal
import subprocess
import time
import uuid
from pathlib import Path



TECHNIQUE_ID   = "T1110.002"
TECHNIQUE_NAME = "Password Cracking"

TOOL_BINARY = "hashcat"           # apt install hashcat  (needs a GPU/OpenCL runtime to be fast)
STATE_DIR = Path(os.environ.get("HASHCAT_STATE_DIR", "/tmp/hashcat_jobs"))
STATE_DIR.mkdir(parents=True, exist_ok=True)


# ─── Tool 1: submit_to_hashcat ─────────────────────────────────────────────
# Fire-and-forget launch. Returns in ~1-2s regardless of how long the actual
# crack takes. This is the tool the agent calls right after kerberoasting.

def submit_to_hashcat(hashes, mode, wordlist, attack_mode=0, rules=None,
                       session=None, extra_args=None):
    """
    Launch hashcat as a detached background job and return immediately.

    hashes:       list of raw hash strings (e.g. the $krb5tgs$... lines from
                  kerberoast.py), or a path to an existing hash file.
    mode:         hashcat -m value (e.g. 13100 for Kerberos TGS-REP etype 23)
    wordlist:     path to wordlist file
    attack_mode:  hashcat -a value (0 = straight/wordlist, default)
    rules:        optional path to a .rule file
    session:      optional session name; auto-generated if omitted
    extra_args:   optional list of additional raw hashcat CLI args

    Does NOT wait for cracking to finish. Poll check_cracked(session) for
    results, and call cancel_job(session) to abandon a job early.
    """
    start = time.monotonic()
    session = session or f"job_{uuid.uuid4().hex[:8]}"
    job_dir = STATE_DIR / session
    job_dir.mkdir(parents=True, exist_ok=True)

    hash_file = job_dir / "hashes.txt"
    potfile = job_dir / "hashcat.potfile"
    status_log = job_dir / "status.jsonl"
    proc_log = job_dir / "hashcat.log"
    meta_file = job_dir / "meta.json"

    hash_count = None
    if isinstance(hashes, (list, tuple)):
        hash_count = len(hashes)
        hash_file.write_text("\n".join(hashes) + "\n")
    else:
        existing = Path(hashes)
        if not existing.exists():
            return _error(session, f"hash source {hashes!r} not found",
                          duration=time.monotonic() - start)
        hash_file.write_text(existing.read_text())
        hash_count = sum(1 for l in hash_file.read_text().splitlines() if l.strip())

    if not Path(wordlist).exists():
        return _error(session, f"wordlist {wordlist!r} not found",
                      duration=time.monotonic() - start)

    cmd = [
        TOOL_BINARY,
        "-m", str(mode),
        "-a", str(attack_mode),
        str(hash_file),
        wordlist,
        "--session", session,
        "--potfile-path", str(potfile),
        "--status",
        "--status-json",
        "--status-timer", "5",
    ]
    if rules:
        cmd += ["--rules-file", rules]
    if extra_args:
        cmd += list(extra_args)

    try:
        status_fh = open(status_log, "w")
        log_fh = open(proc_log, "w")
        proc = subprocess.Popen(
            cmd,
            stdout=status_fh,       # --status-json snapshots land here
            stderr=log_fh,
            start_new_session=True,  # detach — keeps running after this call returns
        )
    except FileNotFoundError:
        return _error(
            session,
            f"{TOOL_BINARY!r} not found on PATH. Install: apt install hashcat",
            duration=time.monotonic() - start,
        )

    # Brief liveness check only (~1s) — this is NOT a crack timeout.
    time.sleep(1)
    alive = proc.poll() is None

    meta = {
        "session": session,
        "pid": proc.pid,
        "mode": mode,
        "attack_mode": attack_mode,
        "wordlist": wordlist,
        "hash_file": str(hash_file),
        "potfile": str(potfile),
        "status_log": str(status_log),
        "proc_log": str(proc_log),
        "started_at": start,
        "cmd": cmd,
    }
    meta_file.write_text(json.dumps(meta, indent=2))

    if not alive:
        tail = proc_log.read_text()[-500:] if proc_log.exists() else ""
        return _error(session, "hashcat exited immediately after launch — bad args/paths/mode?",
                      stderr=tail, duration=time.monotonic() - start)

    return {
        "tool": "hashcat",
        "status": "submitted",
        "summary": (f"Submitted job '{session}' (mode {mode}, {hash_count} hash(es), "
                    f"wordlist {Path(wordlist).name}) — poll check_cracked('{session}')."),
        "data": {"session": session, "pid": proc.pid, "hash_count": hash_count},
        "error": None,
        "raw_stderr_tail": None,
        "duration_seconds": round(time.monotonic() - start, 2),
    }


# ─── Tool 2: check_cracked ──────────────────────────────────────────────────
# Cheap, near-instant. Reads whatever is on disk right now — never blocks on
# hashcat itself. Call this repeatedly instead of waiting on submit.

def check_cracked(session, target_account=None):
    start = time.monotonic()
    job_dir = STATE_DIR / session
    meta_file = job_dir / "meta.json"

    if not meta_file.exists():
        return _error(session, f"no such job — was it submitted with submit_to_hashcat?",
                      duration=time.monotonic() - start)

    meta = json.loads(meta_file.read_text())
    potfile = Path(meta["potfile"])
    status_log = Path(meta["status_log"])
    pid = meta["pid"]

    cracked = _read_potfile(potfile, target_account)
    progress = _latest_status(status_log)
    proc_alive = _pid_alive(pid)

    if cracked:
        return {
            "tool": "hashcat",
            "status": "cracked",
            "summary": f"{len(cracked)} credential(s) recovered for job '{session}'.",
            "data": {"session": session, "cracked": cracked, "progress": progress},
            "error": None,
            "raw_stderr_tail": None,
            "duration_seconds": round(time.monotonic() - start, 2),
        }

    if proc_alive:
        pct = progress.get("progress_pct") if progress else None
        eta = progress.get("estimated_stop") if progress else None
        return {
            "tool": "hashcat",
            "status": "pending",
            "summary": (f"Job '{session}' still running"
                        + (f", {pct}% of candidates tried" if pct is not None else "")
                        + (f", ETA {eta}" if eta else "")
                        + " — no crack yet."),
            "data": {"session": session, "cracked": [], "progress": progress},
            "error": None,
            "raw_stderr_tail": None,
            "duration_seconds": round(time.monotonic() - start, 2),
        }

    # Process ended, potfile empty → wordlist/rules exhausted without a hit
    return {
        "tool": "hashcat",
        "status": "exhausted",
        "summary": f"Job '{session}' finished with no crack — wordlist/rules exhausted for these hashes.",
        "data": {"session": session, "cracked": [], "progress": progress},
        "error": None,
        "raw_stderr_tail": None,
        "duration_seconds": round(time.monotonic() - start, 2),
    }


# ─── Tool 3: cancel_job ─────────────────────────────────────────────────────
# The explicit give-up path. Without this, an agent with only submit/check
# has no way to stop paying attention to a job it has deprioritized — it can
# only keep polling forever or silently ignore it while the GPU keeps running.

def cancel_job(session):
    """
    SIGTERM lets hashcat write a restore checkpoint before exiting, so the
    session could be resumed later outside this wrapper with:
        hashcat --session <session> --restore
    """
    start = time.monotonic()
    job_dir = STATE_DIR / session
    meta_file = job_dir / "meta.json"

    if not meta_file.exists():
        return _error(session, "no such job", duration=time.monotonic() - start)

    meta = json.loads(meta_file.read_text())
    pid = meta["pid"]

    if not _pid_alive(pid):
        return {
            "tool": "hashcat",
            "status": "already_stopped",
            "summary": f"Job '{session}' was not running.",
            "data": {"session": session},
            "error": None,
            "raw_stderr_tail": None,
            "duration_seconds": round(time.monotonic() - start, 2),
        }

    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass

    return {
        "tool": "hashcat",
        "status": "cancelled",
        "summary": f"Sent SIGTERM to job '{session}' (pid {pid}). Restore point preserved for later resume.",
        "data": {"session": session},
        "error": None,
        "raw_stderr_tail": None,
        "duration_seconds": round(time.monotonic() - start, 2),
    }


# ─── Internal helpers ────────────────────────────────────────────────────────

def _read_potfile(potfile, target_account=None):
    if not potfile.exists():
        return []
    found = []
    for line in potfile.read_text().splitlines():
        if not line.strip():
            continue
        hash_part, _, plain = line.partition(":")
        account = None
        m = re.match(r"\$krb5tgs\$\d+\$\*([^$]+)\$", hash_part)
        if m:
            account = m.group(1)
        if target_account and account and target_account.lower() != account.lower():
            continue
        found.append({"account": account or "unknown", "hash": hash_part, "plaintext": plain})
    return found


def _latest_status(status_log):
    if not status_log.exists():
        return None
    last_json_line = None
    with open(status_log) as fh:
        for line in fh:
            line = line.strip()
            if line.startswith("{"):
                last_json_line = line
    if not last_json_line:
        return None
    try:
        raw = json.loads(last_json_line)
    except json.JSONDecodeError:
        return None
    done, total = (raw.get("progress") or [0, 1])
    pct = round(100 * done / total, 2) if total else None
    return {
        "progress_pct": pct,
        "time_started": raw.get("time_started"),
        "estimated_stop": raw.get("estimated_stop"),
        "recovered": raw.get("recovered_hashes"),
        "status_code": raw.get("status"),
    }


def _pid_alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False
    except OSError:
        return False


def _error(session, reason, stderr="", duration=None):
    return {
        "technique_id": TECHNIQUE_ID,
        "technique_name": TECHNIQUE_NAME,
        "tool": "hashcat",
        "status": "error",
        "summary": f"Job '{session}': {reason}",
        "data": None,
        "error": reason,
        "raw_stderr_tail": (stderr or "")[-500:] or None,
        "duration_seconds": round(duration, 2) if duration is not None else None,
    }


# ─── Terminal smoke-test ───────────────────────────────────────────────────
# Usage:
#   python3 hashcat_wrapper.py submit --mode 13100 --wordlist rockyou.txt --hash-file tgs.txt
#   python3 hashcat_wrapper.py check  --session job_ab12cd34
#   python3 hashcat_wrapper.py cancel --session job_ab12cd34

if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Async hashcat wrapper — manual test harness")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("submit")
    sp.add_argument("--mode", type=int, required=True)
    sp.add_argument("--wordlist", required=True)
    sp.add_argument("--hash-file", required=True, help="path to file of hashes (one per line)")
    sp.add_argument("--attack-mode", type=int, default=0)
    sp.add_argument("--rules", default=None)
    sp.add_argument("--session", default=None)

    cp = sub.add_parser("check")
    cp.add_argument("--session", required=True)
    cp.add_argument("--account", default=None)

    kp = sub.add_parser("cancel")
    kp.add_argument("--session", required=True)

    args = ap.parse_args()

    if args.cmd == "submit":
        result = submit_to_hashcat(
            hashes=args.hash_file,
            mode=args.mode,
            wordlist=args.wordlist,
            attack_mode=args.attack_mode,
            rules=args.rules,
            session=args.session,
        )
    elif args.cmd == "check":
        result = check_cracked(session=args.session, target_account=args.account)
    else:
        result = cancel_job(session=args.session)

    print(json.dumps(result, indent=2))