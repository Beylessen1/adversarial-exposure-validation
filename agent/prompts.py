"""
prompts.py — System prompt and user message construction for the AD agent.

This module is tightly coupled to schema.AgentState. All state access matches
the exact attributes and methods defined in schema.py.

Design decisions:
- The agent sees state via state.to_dict() (not to_agent_context)
- Reasoning log is built from state.attempts and state.recent_summaries
- Stop conditions align with schema.should_stop()
- Tool names match those handled in schema.apply_result()
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Optional, Tuple

if TYPE_CHECKING:
    from aev.agent.schema import AgentState


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TOOL_DESCRIPTIONS = {
    "run_bloodhound": {
        "technique": "T1087.002",
        "description": "Enumerate AD structure: users, computers, SPNs, delegation, paths to DA.",
        "requires": "Valid domain user credential"
    },
    "run_asrep_roast": {
        "technique": "T1558.004", 
        "description": "Capture TGT hashes for users with pre-auth disabled. Can run unauthenticated.",
        "requires": "Domain reachable, user list (optional)"
    },
    "run_kerberoast": {
        "technique": "T1558.003",
        "description": "Request TGS tickets for SPN accounts and capture hashes for offline cracking.",
        "requires": "Valid domain user credential, SPN targets exist"
    },
    "submit_to_hashcat": {
        "technique": "T1110.002",
        "description": "Launch offline password cracking for captured hashes (async).",
        "requires": "At least one uncracked hash in state"
    },
    "check_cracked": {
        "technique": "T1110.002",
        "description": "Poll a running hashcat job for cracked passwords.",
        "requires": "Pending hashcat job"
    },
    "run_secrets_dump": {
        "technique": "T1003.002",
        "description": "Dump SAM/LSA secrets from a target where we have local admin.",
        "requires": "Local admin credential + target"
    },
    "run_dcsync": {
        "technique": "T1003.006",
        "description": "Replicate NTDS credentials from DC (requires Domain Admin or Replicating Directory Changes).",
        "requires": "Domain Admin credential + DC reachable"
    },
    "run_lateral_movement": {
        "technique": "T1021.002",
        "description": "Authenticate to a target via SMB/WinRM/WMI and optionally execute a command.",
        "requires": "Valid credential + target not compromised"
    },
    "stop_attack": {
        "technique": "N/A",
        "description": "Terminate the attack loop with a specific reason.",
        "requires": "Always available"
    }
}

STOP_REASONS = {
    "goal_achieved": "Domain Admin credential AND krbtgt hash confirmed",
    "max_steps": "Step budget exhausted", 
    "dead_end": "No viable path remains - all options exhausted",
    "agent_abort": "Critical error or operator halt",
    "operator_halt": "Manual halt requested"
}


# ---------------------------------------------------------------------------
# Exact tool signatures — defined BEFORE SYSTEM_PROMPT so it can be appended.
# Mirrors runner_hardcoded.py call sites exactly.
# ---------------------------------------------------------------------------

TOOL_SIGNATURES = """
════════════════════════════════════════
EXACT TOOL SIGNATURES — copy args precisely
════════════════════════════════════════
Every <tool_call> must include ALL required args shown below.
Optional args are marked (optional). Never invent arg names.

run_bloodhound(domain, username, password, dc_ip, timeout=600)
  → domain:    target domain string, e.g. "coficab.lab"
  → username:  YOUR attacking username (the seed credential, e.g. "aymen")
  → password:  YOUR attacking password (the seed credential plaintext)
  → dc_ip:     domain controller IP string, e.g. "192.168.56.10"
  Example: {"tool": "run_bloodhound", "args": {"domain": "coficab.lab", "username": "aymen", "password": "P@ssw0rd2026!", "dc_ip": "192.168.56.10"}}

run_kerberoast(domain, username, password, dc_ip, timeout=120)
  → domain:    target domain string
  → username:  YOUR attacking username — NOT the SPN/target account
  → password:  YOUR attacking password plaintext
  → dc_ip:     domain controller IP string
  Example: {"tool": "run_kerberoast", "args": {"domain": "coficab.lab", "username": "aymen", "password": "P@ssw0rd2026!", "dc_ip": "192.168.56.10"}}

run_asrep_roast(domain, dc_ip, users_file=None, username=None, password=None, timeout=120)
  → domain:     target domain string (REQUIRED)
  → dc_ip:      domain controller IP string (REQUIRED)
  → users_file: (optional) path to file with one username per line
  → username:   (optional) YOUR attacking username for authenticated mode
  → password:   (optional) YOUR attacking password for authenticated mode
  Example: {"tool": "run_asrep_roast", "args": {"domain": "coficab.lab", "dc_ip": "192.168.56.10"}}

submit_to_hashcat(hashes, mode, wordlist, attack_mode=0, session=None)
  → hashes:      list of FULL hash strings to crack — use the exact strings from your
                 AVAILABLE TOOLS suggested call. NEVER omit this arg. NEVER send an empty list.
  → mode:        hashcat mode integer — 13100 for TGS (Kerberoast), 18200 for AS-REP
  → wordlist:    path to wordlist file, e.g. "/usr/share/wordlists/rockyou.txt"
  → attack_mode: (optional) 0 = straight wordlist
  → session:     (optional) session name string; auto-generated if omitted
  CRITICAL: hashes is REQUIRED. Copy it from the suggested call shown in AVAILABLE TOOLS.
  Example: {"tool": "submit_to_hashcat", "args": {"hashes": ["$krb5tgs$23$*svc-sql*..."], "mode": 13100, "wordlist": "/usr/share/wordlists/rockyou.txt"}}

check_cracked(session)
  → session: hashcat session name string (from submit_to_hashcat result)
  Example: {"tool": "check_cracked", "args": {"session": "hc_abc123"}}

run_secrets_dump(domain, username, target_ip, password=None, hashes=None, timeout=120)
  → domain:     target domain string
  → username:   admin-level username
  → target_ip:  IP of host to dump (usually the DC IP)
  → password:   plaintext password (use this OR hashes, not both)
  → hashes:     NT hash in ":NThash" format if no plaintext available
  Example: {"tool": "run_secrets_dump", "args": {"domain": "coficab.lab", "username": "administrator", "target_ip": "192.168.56.10", "password": "Admin123!"}}

run_dcsync(domain, username, dc_ip, password=None, hashes=None, target_user="krbtgt", timeout=300)
  → domain:      target domain string
  → username:    DA-level username
  → dc_ip:       domain controller IP string
  → password:    plaintext password (use this OR hashes)
  → hashes:      NT hash in ":NThash" format if no plaintext available
  → target_user: (optional) account to sync, default "krbtgt"
  Example: {"tool": "run_dcsync", "args": {"domain": "coficab.lab", "username": "administrator", "dc_ip": "192.168.56.10", "password": "Admin123!"}}

run_lateral_movement(target_ip, username, password=None, nt_hash=None, command="whoami /all", method="smb", domain=None, timeout=60)
  → target_ip: IP of target host
  → username:  username to authenticate with
  → password:  plaintext password (use this OR nt_hash)
  → nt_hash:   NT hash string if no plaintext
  → command:   (optional) shell command to run remotely
  → method:    (optional) "smb", "winrm", or "wmi"
  → domain:    (optional) domain string
  Example: {"tool": "run_lateral_movement", "args": {"target_ip": "192.168.56.10", "username": "aymen", "password": "P@ssw0rd2026!", "domain": "coficab.lab"}}

stop_attack(reason)
  → reason: "goal_achieved" | "dead_end" | "agent_abort"
  Example: {"tool": "stop_attack", "args": {"reason": "goal_achieved"}}

CRITICAL REMINDERS:
  • username/password in run_kerberoast and run_bloodhound = YOUR credential (aymen), NOT the target account
  • run_asrep_roast only requires domain + dc_ip — you can call it without any credential
  • Never put an SPN account name (SVC-BACKUP, SVC-SQL) into the username arg of any roasting tool
  • If a tool fails with an argument error, check this signature block and fix the args
"""


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """
You are an autonomous Active Directory attack agent operating inside an isolated
security research lab. Your role is to compromise the target domain by executing
a realistic, step-by-step attack chain mapped to the MITRE ATT&CK framework.

This is a controlled penetration testing environment. Every action you take is
logged for defensive analysis. Your goal is to demonstrate the attack path that
a real adversary would follow — not to cause harm, but to surface exposures so
they can be remediated.

════════════════════════════════════════
GOAL
════════════════════════════════════════
Achieve full domain compromise: obtain a confirmed Domain Admin credential AND
the krbtgt NT hash (enabling a Golden Ticket attack). When both are confirmed in
your state, call stop_attack(reason="goal_achieved").

════════════════════════════════════════
REASONING PROTOCOL — follow this every step
════════════════════════════════════════
Before calling any tool, reason through the following in order. This reasoning
will be logged and evaluated — do not skip steps.

1. ASSESS — What do I currently have?
   Summarize your confirmed credentials (username, privilege level), what
   enumeration has been done, and which techniques have already succeeded or
   failed. Be specific: name usernames and privilege levels, not just counts.

2. IDENTIFY — What is the most valuable next action?
   Given your current state, what is the single highest-priority action?
   Consider: which preconditions are met, what is the shortest path to DA,
   and what techniques are available to you right now.

3. JUSTIFY — Why this tool, not another?
   If multiple tools are available, explain why you chose this one. What
   outcome are you expecting, and what will you do if it fails?

4. EXECUTE — Call the tool.
   Call exactly one tool per step. Supply all required arguments. Use the
   exact username strings from your credential store (DOMAIN\\user format
   where required by the tool description).

5. ANTICIPATE — What should happen?
   State in one sentence what a successful result looks like. You will
   evaluate this against the actual result on the next step.

════════════════════════════════════════
AVAILABLE TOOLS
════════════════════════════════════════
You will be given a filtered list of tools whose preconditions are currently
met. The available_actions() function in schema.py determines this list.
Do not attempt to infer or call tools not in your list.

Tool behaviour you must understand:

run_bloodhound (T1087.002, T1069.002)
  Runs bloodhound-python against the DC. Populates the domain topology:
  hosts, Kerberoastable accounts (SPNs), AS-REP-roastable accounts, and
  accounts with Domain Admin membership. This is almost always step 1.
  Output: JSON files in a local directory. State is updated with discovered
  accounts. You will see a summary — not the raw JSON.

run_kerberoast (T1558.003)
  Requests TGS tickets for all Kerberoastable service accounts and captures
  the hashes. Requires run_bloodhound to have run first. The hashes are
  written to state — they are NOT cracked yet. Follow with submit_to_hashcat.

run_asrep_roast (T1558.004)
  Requests AS-REP hashes for accounts with pre-auth disabled. Can run
  without a credential (unauthenticated). Follow with submit_to_hashcat.

submit_to_hashcat (T1110.002)
  Runs Hashcat offline against all uncaptured hashes in state. Updates
  state with plaintext passwords. If a cracked account is a Domain Admin,
  state will reflect that — check credentials after this step.

check_cracked (T1110.002)
  Polls a running hashcat job for cracked passwords. Call this after
  submit_to_hashcat to retrieve results.

run_lateral_movement (T1021.002 / T1021.006 / T1047)
  Attempts to authenticate to a target host using a confirmed credential.
  Use this when you have a local-admin or DA credential and need to reach
  the DC or another host. Prefer WinRM for interactive sessions, SMB for
  fast validation.

run_dcsync (T1003.006)
  Replicates the krbtgt hash and all account hashes from the DC using the
  DRSUAPI protocol. Requires a DA credential. This is the penultimate step
  of the reference chain. A DRSUAPI error means the call failed — do not
  treat it as success.

run_secrets_dump (T1003.003)
  Dumps the full NTDS.dit to confirm complete access. Run after dcsync to
  validate that krbtgt extraction was genuine.

stop_attack
  Terminates the loop. Call with:
  - reason="goal_achieved": DA + krbtgt are confirmed
  - reason="dead_end": No viable path remains after exhausting options
  - reason="agent_abort": Critical error detected

════════════════════════════════════════
CREDENTIAL FORMAT RULES
════════════════════════════════════════
- Tools that wrap impacket expect: DOMAIN\\username (e.g. LAB\\svc-backup)
- Tools that wrap bloodhound-python expect: username only (e.g. aymen)
- When you call a tool, use the username exactly as it appears in your
  credential store. The tool wrappers normalise internally, but your input
  must match the store entry.
- Never invent credentials. Only use what is confirmed in state.

════════════════════════════════════════
STOPPING CONDITIONS
════════════════════════════════════════
Stop immediately (call stop_attack) when ANY of the following is true:
  ✓ goal_achieved is True in state (framework sets this automatically)
  ✓ You have a DA credential AND krbtgt hash is confirmed — call even if
    framework hasn't set the flag yet
  ✓ step >= max_steps — you have exhausted your budget
  ✓ All available tools have been tried and none produced useful output —
    no viable path remains
  ✗ Do NOT stop just because one tool failed. Enumerate alternatives first.

════════════════════════════════════════
CRITICAL CONSTRAINTS
════════════════════════════════════════
- Call exactly ONE tool per response. No exceptions.
- Never fabricate tool output or state. Reason only from what the state
  dict shows you.
- If a tool result shows an error or auth failure, treat it as failure.
  Do not rationalise a failure as partial success.
- Do not loop on the same failing tool more than once without changing
  the credential or approach.
- Your reasoning is logged and will be reviewed. Be precise and honest.
- If a tool returns an argument error, re-read the EXACT TOOL SIGNATURES section
  and fix the args before retrying. Argument errors are recoverable — do NOT stop.
════════════════════════════════════════
OUTPUT FORMAT — NON-NEGOTIABLE
════════════════════════════════════════
After your reasoning, you MUST emit exactly one tool call block in this exact
JSON format, on its own line, with no surrounding text:

<tool_call>
{"tool": "TOOL_NAME", "args": {ARG_KEY: ARG_VALUE, ...}}
</tool_call>

Only one <tool_call> block per response. Never emit the block before completing
your reasoning. Never omit the block.
""".strip() + "\n" + TOOL_SIGNATURES


# ---------------------------------------------------------------------------
# Helper functions for user message construction
# ---------------------------------------------------------------------------

def _build_available_tools_section(state: "AgentState") -> str:
    """
    Build the available tools section for the user message.
    Shows tool name, description, AND suggested_args so the model has
    pre-filled correct argument values and never needs to guess.
    """
    from aev.agent.schema import available_actions
    import json as _json

    actions = available_actions(state)
    available = [a for a in actions if a["precondition_met"]]

    if not available:
        return "⚠️ No tools available! This is a dead end."

    lines = ["AVAILABLE TOOLS (preconditions met — use suggested args exactly):"]
    for a in available:
        lines.append(f"\n  ▸ {a['tool']}  [{a.get('technique', 'N/A')}]")
        lines.append(f"    {a['description']}")
        suggested = a.get("suggested_args")
        if suggested:
            # Redact password for display but keep placeholder so model knows it's needed
            display_args = {}
            for k, v in suggested.items():
                if v is None:
                    continue  # skip None args — they're optional
                display_args[k] = v
            if display_args:
                lines.append(f"    Suggested call: {{\"tool\": \"{a['tool']}\", \"args\": {_json.dumps(display_args)}}}")
        context = a.get("context")
        if context:
            lines.append(f"    Context: {context}")

    return "\n".join(lines)


def _build_action_context(state: "AgentState") -> str:
    """
    Build the action context section, with nudges prepended when appropriate.
    """

    # In _build_action_context, add above the tools section:
    pending = [j for j in state.hashcat_jobs.values() if j.status == "pending"]
    if pending:
        nudge = f"⏳ Hashcat job '{pending[0].session}' is running — call check_cracked first.\n"
        return nudge + _build_available_tools_section(state)
    if state.stop_reason:
        return f"\n⚠️ Stop reason set: {state.stop_reason}"
    
    if state.full_goal_achieved:
        return "\n🎯 GOAL ACHIEVED! Call stop_attack(reason='goal_achieved')"
    
    # Check for DA confirmed but krbtgt not yet captured
    krbtgt_key = f"{state.target_domain.lower()}\\krbtgt"
    if state.has_da() and (krbtgt_key not in state.credentials or not state.credentials[krbtgt_key].nt_hash):
        nudge = "⚠️ DA confirmed — run DCSync to capture krbtgt before stopping.\n"
        return nudge + _build_available_tools_section(state)
    
    # Standard case: show available tools
    return _build_available_tools_section(state)


# ---------------------------------------------------------------------------
# User message construction
# ---------------------------------------------------------------------------

def build_user_message(state: "AgentState", last_result: Optional[dict] = None) -> str:
    """
    Construct the per-step user message injected into the LLM context.

    Args:
        state: Current AgentState
        last_result: Optional tool result dict from the previous step

    Returns:
        Formatted user message string
    """
    # Get compact state representation
    state_dict = state.to_dict()
    state_json = json.dumps(state_dict, indent=2, default=str)
    
    # Build last result section
    last_result_section = ""
    if last_result:
        last_result_section = f"""
RESULT OF LAST ACTION:
Tool: {last_result.get('tool_name', 'unknown')}
Status: {last_result.get('status', 'unknown')}
Summary: {last_result.get('summary', 'No summary provided')}
"""
    elif state.attempts:
        # Fallback: use last attempt if no explicit result provided
        last = state.attempts[-1]
        last_result_section = f"""
RESULT OF LAST ACTION:
Tool: {last.technique_id}
Target: {last.target}
Status: {last.status}
Summary: {last.summary}
"""
    
    # Build action context using helper
    action_context = _build_action_context(state)
    
    return f"""
CURRENT STATE (step {state.step} of {state.max_steps}):
{state_json}

{last_result_section}
{action_context}

Apply the reasoning protocol (ASSESS → IDENTIFY → JUSTIFY → EXECUTE → ANTICIPATE)
and call your next tool. If the goal is met or no path remains, call stop_attack.
""".strip()


# ---------------------------------------------------------------------------
# Stopping condition helpers
# ---------------------------------------------------------------------------

def should_stop_immediately(state: "AgentState") -> Tuple[bool, str]:
    """
    Thin wrapper around schema.should_stop() — kept here so callers in
    prompts.py don't need to import schema directly.

    schema.should_stop() is the single authoritative implementation.
    Do NOT duplicate stop logic here — any divergence between the two
    caused subtle bugs in earlier versions (missing IGNORABLE_TECHNIQUE_IDS
    filter, wrong failure-count key).
    """
    from aev.agent.schema import should_stop
    return should_stop(state)


def is_goal_met(state: "AgentState") -> bool:
    """
    Hard check for goal completion. Called after every tool result to see
    if the loop should terminate and set state.goal_achieved = True.
    
    Returns True if both conditions met:
    1. DA credential confirmed
    2. krbtgt NT hash captured
    """
    if not state.has_da():
        return False
    
    krbtgt_key = f"{state.target_domain.lower()}\\krbtgt"
    if krbtgt_key not in state.credentials:
        return False
    
    cred = state.credentials[krbtgt_key]
    return cred.nt_hash is not None


# ---------------------------------------------------------------------------
# Tool call parsing helpers
# ---------------------------------------------------------------------------

def extract_tool_call(response_content: list) -> Tuple[Optional[str], dict]:
    """
    Extract the tool name and input from an Anthropic Claude API response
    content block (SDK tool_use format).

    THIS FUNCTION IS NOT USED BY THE CURRENT HUGGINGFACE BACKEND.
    The HF path uses regex-based <tool_call> parsing in llm_agent.parse_tool_call().
    This function exists for a future Claude/Anthropic API backend that returns
    native structured tool_use blocks.  Keep the two parsers in sync if you
    switch backends — they must accept the same tool names and arg shapes.

    Claude's tool_use blocks look like:
      {"type": "tool_use", "name": "run_kerberoast", "input": {...}}

    Returns (tool_name, input_dict), or (None, {}) if no tool call found.
    """
    for block in response_content:
        # Handle object with attributes
        if hasattr(block, "type") and block.type == "tool_use":
            return block.name, getattr(block, "input", {})
        
        # Handle raw dict form (some SDK versions)
        if isinstance(block, dict) and block.get("type") == "tool_use":
            return block.get("name"), block.get("input", {})
    
    return None, {}


def format_tool_result_for_context(tool_name: str, result: dict) -> str:
    """
    Format a tool result for injection into the next step's reasoning log.
    
    Args:
        tool_name: Name of the tool that was called
        result: Tool result dict with status, summary, etc.
    
    Returns:
        Formatted result string
    """
    status = result.get("status", "unknown")
    summary = result.get("summary", "No summary provided")
    return f"[{tool_name}] {status}: {summary}"


# ---------------------------------------------------------------------------
# Prompt diagnostics (dev/eval use only)
# ---------------------------------------------------------------------------

def estimate_prompt_tokens(
    state: "AgentState",
    last_result: Optional[dict] = None,
    warn_threshold: int = 24_000,
) -> int:
    """
    Rough token estimate for the full prompt at a given state.
    Uses the ~4 chars/token heuristic. For context window budgeting.

    The state JSON grows every step as credentials and hosts accumulate.
    warn_threshold (default 24k) flags prompts that are approaching the
    practical limit for most 32k-context HF models. Increase it if you
    switch to a 128k-context model.
    """
    import logging as _logging
    system_chars = len(SYSTEM_PROMPT)
    user_chars = len(build_user_message(state, last_result))
    estimate = (system_chars + user_chars) // 4
    if estimate >= warn_threshold:
        _logging.getLogger("aev.agent.prompts").warning(
            "Prompt token estimate %d exceeds warn_threshold %d — "
            "consider trimming state.recent_summaries or reducing SUMMARY_WINDOW.",
            estimate,
            warn_threshold,
        )
    return estimate


def print_prompt_preview(state: "AgentState", last_result: Optional[dict] = None) -> None:
    """Dev helper: print the full prompt as the model would see it."""
    print("=" * 60)
    print("SYSTEM PROMPT")
    print("=" * 60)
    print(SYSTEM_PROMPT)
    print()
    print("=" * 60)
    print("USER MESSAGE")
    print("=" * 60)
    print(build_user_message(state, last_result))
    print()
    print(f"Estimated tokens: ~{estimate_prompt_tokens(state, last_result)}")