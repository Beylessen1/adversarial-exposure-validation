import glob
import json
import os
import shutil
import subprocess
import tempfile
import time

TECHNIQUE_ID   = "T1087.002"
TECHNIQUE_NAME = "Domain Account Discovery"


def run_bloodhound(domain, username, password, dc_ip, timeout=600):
    """Run bloodhound-python collection and return a structured result."""
    start = time.monotonic()
    run_dir = tempfile.mkdtemp(prefix="bh_run_")

    cmd = [
        "bloodhound-python",
        "-u", username, "-p", password,
        "-d", domain, "-ns", dc_ip,
        "-c", "All",
    ]

    try:
        result = subprocess.run(
            cmd, cwd=run_dir, capture_output=True,
            text=True, timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired as e:
        return _error_result("collection timed out", stderr=e.stderr,
                              duration=time.monotonic() - start)
    except FileNotFoundError:
        return _error_result("bloodhound-python not found on PATH",
                              duration=time.monotonic() - start)

    try:
        json_files = glob.glob(os.path.join(run_dir, "*.json"))

        if not json_files:
            # Zero output files is almost always an auth/connectivity failure —
            # even if the exit code claims success.
            return _error_result(
                "no output produced — likely authentication or connectivity failure",
                stderr=result.stderr, duration=time.monotonic() - start,
            )

        parsed = _parse_bloodhound_files(json_files)
        summary = _build_summary(parsed)

        return {
            "technique_id": TECHNIQUE_ID,
            "technique_name": TECHNIQUE_NAME,
            "tool": "bloodhound-python",
            "status": "success",
            "summary": summary,
            "data": parsed,
            "error": None,
            "raw_stderr_tail": None,
            "duration_seconds": time.monotonic() - start,
        }
    except Exception as e:
        return _error_result(f"unexpected error: {e}", stderr=result.stderr,
                              duration=time.monotonic() - start)
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)  # clean up temp files


def _parse_bloodhound_files(json_files):
    summary = {
        "counts": {},
        "kerberoastable_users": [],
        "admincount_users": [],
        "unconstrained_delegation_computers": [],
    }
    for path in json_files:
        with open(path, "r") as f:
            data = json.load(f)
        kind = data.get("meta", {}).get("type", "unknown")
        objects = data.get("data", [])
        summary["counts"][kind] = len(objects)

        if kind == "users":
            for u in objects:
                props = u.get("Properties", {})
                if props.get("hasspn"):
                    summary["kerberoastable_users"].append(props.get("name"))
                if props.get("admincount"):
                    summary["admincount_users"].append(props.get("name"))
        elif kind == "computers":
            for c in objects:
                props = c.get("Properties", {})
                if props.get("unconstraineddelegation"):
                    summary["unconstrained_delegation_computers"].append(props.get("name"))
    return summary


def _build_summary(parsed):
    counts_str = ", ".join(f"{v} {k}" for k, v in parsed["counts"].items())
    return (
        f"Collected AD data: {counts_str}. "
        f"{len(parsed['kerberoastable_users'])} Kerberoastable users, "
        f"{len(parsed['unconstrained_delegation_computers'])} computers with "
        f"unconstrained delegation."
    )


def _error_result(reason, stdout="", stderr="", duration=None):
    return {
        "technique_id": TECHNIQUE_ID,
        "technique_name": TECHNIQUE_NAME,
        "tool": "bloodhound-python",
        "status": "timeout" if "timed out" in reason else "error",
        "summary": f"BloodHound collection failed: {reason}",
        "data": None,
        "error": reason,
        "raw_stderr_tail": (stderr or "")[-500:] or None,
        "duration_seconds": duration,
    }


if __name__ == "__main__":
    result = run_bloodhound(
        domain="coficab.lab",
        username="aymen",
        password="P@ssw0rd2026!",
        dc_ip="192.168.56.10",
    )
    import json as _json
    print(_json.dumps(result, indent=2))