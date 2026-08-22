"""
llm_agent.py — LLM-driven Active Directory attack agent.

Architecture
────────────
This module owns the outer attack loop. It:
  1.  Builds the prompt (via prompts.py)
  2.  Queries the LLM (HuggingFace Inference API, text-generation endpoint)
  3.  Parses the <tool_call> JSON block from the model's text response
  4.  Dispatches the call to the correct tool wrapper
  5.  Merges the result back into AgentState (via schema.apply_result)
  6.  Decides whether to keep looping (via schema.should_stop)
  7.  Writes a JSONL run log to runs/<run_id>.jsonl

The agent is intentionally stateless between runs — all persistent context
lives in AgentState and is serialised to the run log.

"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import requests
from dotenv import load_dotenv

# ── local imports ─────────────────────────────────────────────────────────────
from aev.agent.schema import (
    AgentState,
    Credential,
    HostRecord,
    PrivilegeLevel,
    apply_result,
    available_actions,
    should_stop,
)
from aev.agent.prompts import (
    SYSTEM_PROMPT,
    build_user_message,
    extract_tool_call,
    format_tool_result_for_context,
    estimate_prompt_tokens,
)

# ── tool wrappers ─────────────────────────────────────────────────────────────
# Each wrapper must return the standard result dict:
#   {"status": "success"|"error"|"timeout", "summary": str, "data": dict,
#    "technique_id": str, "tool_name": str}
from aev.tools.enum_bloodhound import run_bloodhound
from aev.tools.kerberoast import run_kerberoast
from aev.tools.asrep_roast import run_asrep_roast
from aev.tools.secrets_dump import run_secrets_dump
from aev.tools.dcsync import run_dcsync
from aev.tools.lateral_movement import run_lateral_movement

# ── logging ───────────────────────────────────────────────────────────────────
load_dotenv(override=False)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("aev.agent.llm")

# ──────────────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────────────

HF_BASE_URL_DEFAULT = "https://router.huggingface.co/v1"
RUNS_DIR = Path("runs")

# Tool names the model is allowed to emit — mapped to callable wrappers.
# stop_attack and hashcat jobs are handled inline (no wrapper import needed).
TOOL_REGISTRY: Dict[str, Any] = {
    "run_bloodhound":     run_bloodhound,
    "run_kerberoast":     run_kerberoast,
    "run_asrep_roast":    run_asrep_roast,
    "run_secrets_dump":   run_secrets_dump,
    "run_dcsync":         run_dcsync,
    "run_lateral_movement": run_lateral_movement,
    # submit_to_hashcat / check_cracked are handled in _dispatch_tool
    # stop_attack is handled in the main loop
}


@dataclass
class AgentConfig:
    """
    Runtime configuration for a single agent run.
    All values come from CLI args or env vars — never hardcoded.
    """
    domain:       str
    dc_ip:        str
    username:     str             # seed credential username
    password:     str             # seed credential plaintext
    nt_hash:      Optional[str]   = None   # alternative to password
    max_steps:    int             = 30
    wordlist:     str             = "/usr/share/wordlists/rockyou.txt"
    run_id:       str             = field(default_factory=lambda: uuid.uuid4().hex[:8])
    hf_api_key:   str             = field(default_factory=lambda: os.getenv("HF_API_KEY", ""))
    hf_model_id:  str             = field(default_factory=lambda: os.getenv("HF_MODEL_ID", "Qwen/Qwen2.5-72B-Instruct"))
    hf_base_url:  str             = field(default_factory=lambda: os.getenv("HF_BASE_URL", HF_BASE_URL_DEFAULT))
    temperature:  float           = 0.2    # low = more deterministic planning
    max_tokens:   int             = 4096


# ──────────────────────────────────────────────────────────────────────────────
# Run log helpers
# ──────────────────────────────────────────────────────────────────────────────

class RunLogger:
    """
    Writes one JSONL line per step to runs/<run_id>.jsonl.
    Each line captures: step, timestamp, tool called, result status, and
    the full serialised AgentState so the run can be replayed for eval.
    """

    def __init__(self, run_id: str) -> None:
        RUNS_DIR.mkdir(exist_ok=True)
        self.path = RUNS_DIR / f"{run_id}.jsonl"
        self._fh = self.path.open("a", encoding="utf-8")
        log.info("Run log → %s", self.path)

    def write(self, record: dict) -> None:
        record["_ts"] = datetime.now(timezone.utc).isoformat()
        self._fh.write(json.dumps(record, default=str) + "\n")
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()


# ──────────────────────────────────────────────────────────────────────────────
# HuggingFace LLM client
# ──────────────────────────────────────────────────────────────────────────────

class HFClient:
    """
    Thin wrapper around the HuggingFace OpenAI-compatible chat completions
    endpoint.  Raises on HTTP errors; returns the assistant message string.

    Retry strategy: up to 3 attempts with exponential backoff on 5xx or
    rate-limit (429) responses. Hard fail on 4xx (auth / model not found).
    """

    def __init__(self, cfg: AgentConfig) -> None:
        if not cfg.hf_api_key:
            raise RuntimeError(
                "HF_API_KEY is not set. "
                "Export it in your shell or add it to .env"
            )
        self.cfg = cfg
        self.endpoint = f"{cfg.hf_base_url.rstrip('/')}/chat/completions"
        self.headers = {
            "Authorization": f"Bearer {cfg.hf_api_key}",
            "Content-Type":  "application/json",
            "HTTP-Referer":  "https://coficab-aev.lab",
            "X-Title":       "AEV Framework",
        }

    def chat(self, system: str, user: str) -> str:
        """
        Send a two-turn (system + user) chat request and return the
        assistant's raw text response.
        """
        payload = {
            "model": self.cfg.hf_model_id,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
            "temperature": self.cfg.temperature,
            "max_tokens":  self.cfg.max_tokens,
            "stream":      False,
        }

        last_err: Optional[Exception] = None
        for attempt in range(1, 4):
            try:
                resp = requests.post(
                    self.endpoint,
                    headers=self.headers,
                    json=payload,
                    timeout=120,
                )
                if resp.status_code in (429, 500, 502, 503, 504):
                    wait = 2 ** attempt
                    log.warning(
                        "HF API %s — retrying in %ds (attempt %d/3)",
                        resp.status_code, wait, attempt,
                    )
                    time.sleep(wait)
                    last_err = RuntimeError(f"HTTP {resp.status_code}")
                    continue

                resp.raise_for_status()
                data = resp.json()
                return data["choices"][0]["message"]["content"]

            except requests.RequestException as exc:
                last_err = exc
                log.warning("Request error: %s (attempt %d/3)", exc, attempt)
                time.sleep(2 ** attempt)

        raise RuntimeError(f"LLM call failed after 3 attempts: {last_err}")


# ──────────────────────────────────────────────────────────────────────────────
# Tool call extraction — text-based (no native function calling)
# ──────────────────────────────────────────────────────────────────────────────

_TOOL_CALL_RE = re.compile(
    r"<tool_call>\s*(\{.*?\})\s*</tool_call>",
    re.DOTALL,
)


def parse_tool_call(response_text: str) -> Tuple[Optional[str], dict]:
    """
    Extract the tool name and args from the model's raw text response.

    The system prompt instructs the model to emit exactly one block:
        <tool_call>
        {"tool": "TOOL_NAME", "args": {...}}
        </tool_call>

    Returns (tool_name, args_dict) or (None, {}) if no valid block found.
    Falls back to extract_tool_call from prompts.py for SDK-style blocks.
    """
    match = _TOOL_CALL_RE.search(response_text)
    if not match:
        # prompts.py helper handles Anthropic SDK-style {"type":"tool_use",...}
        # objects — not applicable here, but kept for completeness.
        return extract_tool_call([])

    raw_json = match.group(1).strip()
    try:
        parsed = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        log.error("Failed to parse tool_call JSON: %s\nRaw: %s", exc, raw_json)
        return None, {}

    tool_name = parsed.get("tool")
    args      = parsed.get("args", {})

    if not isinstance(tool_name, str) or not tool_name:
        log.error("tool_call block missing 'tool' key: %s", parsed)
        return None, {}
    if not isinstance(args, dict):
        log.error("tool_call 'args' must be a dict, got: %s", type(args))
        return None, {}

    return tool_name, args


# ──────────────────────────────────────────────────────────────────────────────
# Hashcat stub (inline — no external wrapper needed)
# ──────────────────────────────────────────────────────────────────────────────

def _stub_submit_to_hashcat(state: AgentState, args: dict) -> dict:
    """
    Delegate to the hashcat tool if available, otherwise return a
    structured stub result so the agent loop doesn't crash in environments
    without GPU / hashcat installed.

    The stub marks the job as 'pending' so check_cracked can be called next
    step — which will immediately return exhausted in lab setups without
    hashcat, preventing the agent from looping on cracking indefinitely.

    NOTE: state is NOT passed to the real wrapper — submit_to_hashcat() takes
    only (hashes, mode, wordlist, ...) and does not accept a state kwarg.
    State is used here only to populate the stub fallback result.
    """
    try:
        from aev.tools import hashcat as hashcat_mod  # optional dependency
        # If model omitted hashes, pull them from state so the call still works
        if (
            "hashes" not in args
            or not args["hashes"]
            or (len(args["hashes"]) == 1 and str(args["hashes"][0]).startswith("<"))
        ):
            args = dict(args)
            args["hashes"] = [
                note.split(": ", 1)[1]
                for cred in state.get_crackable_hashes()
                for note in cred.notes
                if ": " in note and not note.split(": ", 1)[1].endswith("...")
            ]
        return hashcat_mod.submit_to_hashcat(**args)  # no state= kwarg
    except ImportError:
        session = f"hc_{uuid.uuid4().hex[:6]}"
        log.warning("hashcat module not found — returning stub pending result")
        return {
            "status":       "success",
            "technique_id": "T1110.002",
            "tool_name":    "submit_to_hashcat",
            "summary":      f"Hashcat job {session} submitted (stub — no GPU in this environment).",
            "data": {
                "session":    session,
                "pid":        None,
                "mode":       args.get("mode", 0),
                "hash_count": len(state.get_crackable_hashes()),
                "wordlist":   args.get("wordlist", state.wordlist_path),
            },
        }


def _stub_check_cracked(state: AgentState, args: dict) -> dict:
    """
    Poll a hashcat session. Falls back to stub if the hashcat module is absent.
    """
    try:
        from aev.tools import hashcat as hashcat_mod
        return hashcat_mod.check_cracked(**args)
    except ImportError:
        session = args.get("session", "unknown")
        log.warning("hashcat module not found — returning stub exhausted result")
        return {
            "status":       "success",
            "technique_id": "T1110.002",
            "tool_name":    "check_cracked",
            "summary":      f"Hashcat session {session}: exhausted (no GPU stub).",
            "data": {
                "session": session,
                "status":  "exhausted",
                "cracked": [],
            },
        }


# ──────────────────────────────────────────────────────────────────────────────
# Signature hint extractor (used in ARG_ERROR feedback)
# ──────────────────────────────────────────────────────────────────────────────

def _extract_signature_hint(tool_name: str) -> str:
    """
    Pull the one-liner signature for *tool_name* from TOOL_SIGNATURES so it
    can be embedded in an ARG_ERROR result dict.  The model sees it in the
    next step's user message without needing the full system prompt in context.

    Returns the first line that starts with the tool name, or a generic
    fallback pointing to the signature block.
    """
    from aev.agent.prompts import TOOL_SIGNATURES
    for line in TOOL_SIGNATURES.splitlines():
        stripped = line.strip()
        if stripped.startswith(tool_name + "("):
            return stripped
    return f"(see EXACT TOOL SIGNATURES section for {tool_name})"


# ──────────────────────────────────────────────────────────────────────────────
# Tool dispatch
# ──────────────────────────────────────────────────────────────────────────────

def _dispatch_tool(tool_name: str, args: dict, state: AgentState) -> dict:
    """
    Route a parsed tool call to the correct wrapper function.

    All wrappers receive keyword args matching their own signatures.
    The state is passed where needed (hashcat, lateral movement) so
    wrappers can read accumulated context (e.g. known hosts, credentials).

    Returns a standard result dict:
        {
            "status":       "success" | "error" | "timeout" | "exhausted",
            "technique_id": str,   # MITRE ID
            "tool_name":    str,
            "summary":      str,
            "data":         dict,  # technique-specific payload
        }
    """
    # ── meta-actions (handled in caller, should not reach here) ───────────────
    if tool_name == "stop_attack":
        # Caller handles this; returning a stub so dispatch is never None.
        return {
            "status":       "success",
            "technique_id": "N/A",
            "tool_name":    "stop_attack",
            "summary":      f"stop_attack called with reason={args.get('reason')}",
            "data":         {"reason": args.get("reason", "unknown")},
        }

    # ── hashcat (optional dependency, stubbed if absent) ──────────────────────
    if tool_name == "submit_to_hashcat":
        return _stub_submit_to_hashcat(state, args)

    if tool_name in ("check_cracked", "hashcat"):
        return _stub_check_cracked(state, args)

    # ── registered tool wrappers ──────────────────────────────────────────────
    fn = TOOL_REGISTRY.get(tool_name)
    if fn is None:
        log.error("Unknown tool requested by LLM: %r", tool_name)
        return {
            "status":       "error",
            "technique_id": "UNKNOWN",
            "tool_name":    tool_name,
            "summary":      f"No registered wrapper for tool '{tool_name}'.",
            "data":         {},
        }

    try:
        log.info("  → calling %s(%s)", tool_name, _fmt_args(args))
        result = fn(**args)
        if not isinstance(result, dict):
            raise TypeError(f"Wrapper {tool_name} returned {type(result)}, expected dict")
        # Ensure tool_name is always stamped on the result
        result.setdefault("tool_name", tool_name)
        return result

    except TypeError as exc:
        # Argument mismatch — model used wrong arg names or omitted required ones.
        # Extract just the relevant signature line from TOOL_SIGNATURES and
        # embed it directly in the error result so the model sees the fix in
        # the next step's user message, without needing to re-read the system
        # prompt (which is not in its working context for that step).
        log.error("Argument error calling %s: %s", tool_name, exc)
        sig_hint = _extract_signature_hint(tool_name)
        return {
            "status":       "error",
            "technique_id": "ARG_ERROR",
            "tool_name":    tool_name,
            "summary": (
                f"Argument error calling {tool_name}: {exc}. "
                f"Fix the args and retry — this is NOT a dead end.\n"
                f"Correct signature: {sig_hint}"
            ),
            "data":         {},
        }

    except Exception as exc:  # noqa: BLE001
        log.exception("Unexpected error calling %s", tool_name)
        return {
            "status":       "error",
            "technique_id": "RUNTIME_ERROR",
            "tool_name":    tool_name,
            "summary":      f"Runtime error: {exc}",
            "data":         {},
        }


def _fmt_args(args: dict) -> str:
    """Redact passwords/hashes for log display."""
    redacted = {}
    for k, v in args.items():
        if any(s in k.lower() for s in ("password", "hash", "secret", "key")):
            redacted[k] = "***"
        else:
            redacted[k] = v
    return ", ".join(f"{k}={v!r}" for k, v in redacted.items())


# ──────────────────────────────────────────────────────────────────────────────
# Precondition guard
# ──────────────────────────────────────────────────────────────────────────────

def _validate_preconditions(tool_name: str, state: AgentState) -> Optional[str]:
    """
    Cross-check the model's chosen tool against schema.available_actions().
    Returns None if the tool is allowed, or an error string if blocked.

    This prevents the model from calling, e.g., run_dcsync before having DA.
    """
    if tool_name == "stop_attack":
        return None  # always permitted

    actions = available_actions(state)
    for action in actions:
        if action["tool"] == tool_name:
            if action["precondition_met"]:
                return None
            else:
                return action.get("blocked_reason", "precondition not met")

    return f"Tool '{tool_name}' is not in available_actions for the current state."


# ──────────────────────────────────────────────────────────────────────────────
# Main agent class
# ──────────────────────────────────────────────────────────────────────────────

class LLMAgent:
    """
    The outer attack loop.

    Lifecycle
    ─────────
      __init__  → initialise state, seed credential, LLM client, run logger
      run()     → main loop until should_stop() or stop_attack called
      _step()   → single iteration: prompt → LLM → parse → dispatch → merge

    The agent never modifies state directly; all mutations go through
    apply_result() and AgentState helper methods (add_credential, add_host).
    """

    def __init__(self, cfg: AgentConfig) -> None:
        self.cfg    = cfg
        self.client = HFClient(cfg)
        self.logger = RunLogger(cfg.run_id)

        # ── initialise state ──────────────────────────────────────────────────
        self.state = AgentState(
            target_domain=cfg.domain,
            dc_ip=cfg.dc_ip,
            wordlist_path=cfg.wordlist,
            max_steps=cfg.max_steps,
        )

        # ── seed credential ───────────────────────────────────────────────────
        seed = Credential(
            username=cfg.username,
            domain=cfg.domain,
            plaintext=cfg.password if cfg.password else None,
            nt_hash=cfg.nt_hash,
            privilege_level=PrivilegeLevel.USER,
            source_technique="seed",
            notes=["Provided at agent startup"],
        )
        self.state.add_credential(seed)
        log.info("Seed credential: %s (USER)", seed.key)

        # ── seed DC host (we know the IP from config) ─────────────────────────
        dc_host = HostRecord(
            ip=cfg.dc_ip,
            domain=cfg.domain,
            roles=["dc"],
            notes=["Provided at agent startup"],
        )
        self.state.add_host(dc_host)

        # ── write run header ──────────────────────────────────────────────────
        self.logger.write({
            "event":    "run_start",
            "run_id":   cfg.run_id,
            "domain":   cfg.domain,
            "dc_ip":    cfg.dc_ip,
            "username": cfg.username,
            "model":    cfg.hf_model_id,
            "max_steps": cfg.max_steps,
        })

        log.info(
            "LLMAgent initialised — run_id=%s  domain=%s  dc=%s  model=%s",
            cfg.run_id, cfg.domain, cfg.dc_ip, cfg.hf_model_id,
        )

    # ── public API ─────────────────────────────────────────────────────────────

    def run(self) -> AgentState:
        """
        Execute the attack loop until a terminal condition is reached.
        Returns the final AgentState.
        """
        log.info("=" * 60)
        log.info("ATTACK LOOP START — max_steps=%d", self.cfg.max_steps)
        log.info("=" * 60)

        last_result: Optional[dict] = None

        while True:
            # ── pre-step terminal check (before incrementing) ─────────────────
            # Check stop BEFORE incrementing so that max_steps=20 means the
            # model gets exactly 20 steps, not 21.  step is incremented only
            # when we know we are going to execute this iteration.
            stop, reason = should_stop(self.state)
            if stop:
                log.info("[step %d] Pre-step stop: %s", self.state.step, reason)
                self.state.stop_reason = reason
                self._finalize(reason)
                break

            self.state.step += 1
            step = self.state.step
            log.info("[step %d/%d] ─────────────────────────────", step, self.cfg.max_steps)

            # ── run one step ──────────────────────────────────────────────────
            should_break, last_result = self._step(last_result)
            if should_break:
                break

        self.logger.close()
        self._print_summary()
        return self.state

    # ── single step ───────────────────────────────────────────────────────────

    def _step(self, last_result: Optional[dict]) -> Tuple[bool, Optional[dict]]:
        """
        Execute one agent step: prompt → LLM → parse → guard → dispatch → merge.

        Returns (should_break: bool, result: Optional[dict]).
        """
        step = self.state.step

        # 1. Build prompt ──────────────────────────────────────────────────────
        user_msg = build_user_message(self.state, last_result)
        est_tokens = estimate_prompt_tokens(self.state, last_result)
        log.debug("Prompt ~%d tokens", est_tokens)

        # 2. Query LLM ─────────────────────────────────────────────────────────
        log.info("[step %d] Querying %s …", step, self.cfg.hf_model_id)
        t0 = time.monotonic()
        try:
            response_text = self.client.chat(SYSTEM_PROMPT, user_msg)
        except RuntimeError as exc:
            log.error("[step %d] LLM call failed: %s", step, exc)
            self.state.stop_reason = "agent_abort"
            self._finalize("agent_abort")
            return True, None
        elapsed = time.monotonic() - t0
        log.info("[step %d] LLM responded in %.1fs", step, elapsed)

        # Log reasoning excerpt (first 600 chars to keep log readable)
        reasoning_excerpt = response_text[:600].replace("\n", " ")
        log.info("[step %d] Reasoning: %s…", step, reasoning_excerpt)

        # 3. Parse tool call ───────────────────────────────────────────────────
        tool_name, args = parse_tool_call(response_text)

        if tool_name is None:
            # The model produced reasoning but forgot the <tool_call> block —
            # this is common with smaller HF models.  Retry once with an explicit
            # correction prompt before aborting the run.
            log.warning(
                "[step %d] No <tool_call> block found — retrying with correction prompt.",
                step,
            )
            correction_msg = (
                f"{user_msg}\n\n"
                f"[SYSTEM CORRECTION] Your previous response did not contain a "
                f"<tool_call> block. You MUST end your response with exactly:\n\n"
                f"<tool_call>\n"
                f'{{\"tool\": \"TOOL_NAME\", \"args\": {{...}}}}\n'
                f"</tool_call>\n\n"
                f"Your previous response was:\n{response_text[:800]}\n\n"
                f"Repeat your reasoning briefly and then emit the <tool_call> block."
            )
            try:
                response_text = self.client.chat(SYSTEM_PROMPT, correction_msg)
                tool_name, args = parse_tool_call(response_text)
            except RuntimeError as exc:
                log.error("[step %d] Correction retry LLM call failed: %s", step, exc)
                tool_name = None

        if tool_name is None:
            log.error(
                "[step %d] No <tool_call> block found after correction retry. "
                "Full response logged. Aborting.",
                step,
            )
            self.logger.write({
                "event":          "parse_failure",
                "step":           step,
                "response_text":  response_text,
            })
            self.state.stop_reason = "agent_abort"
            self._finalize("agent_abort")
            return True, None

        log.info("[step %d] Tool chosen: %s  args=%s", step, tool_name, _fmt_args(args))

        # 4. Handle stop_attack immediately ────────────────────────────────────
        if tool_name == "stop_attack":
            reason = args.get("reason", "unknown")
            log.info("[step %d] Agent called stop_attack(reason=%r)", step, reason)
            self.state.stop_reason = reason
            self.logger.write({
                "event":  "stop_attack",
                "step":   step,
                "reason": reason,
                "state":  self.state.to_dict(),
            })
            self._finalize(reason)
            return True, None

        # 5. Precondition guard ────────────────────────────────────────────────
        guard_error = _validate_preconditions(tool_name, self.state)
        if guard_error:
            log.warning(
                "[step %d] Precondition guard blocked %s: %s",
                step, tool_name, guard_error,
            )
            # Inject a synthetic failed result so the model sees the block
            result = {
                "status":       "error",
                "technique_id": "PRECONDITION_BLOCKED",
                "tool_name":    tool_name,
                "summary":      f"BLOCKED: {guard_error}",
                "data":         {},
            }
            self._record_and_log(step, tool_name, result, response_text)
            return False, result

        # 6. Dispatch to wrapper ───────────────────────────────────────────────
        result = _dispatch_tool(tool_name, args, self.state)
        log.info(
            "[step %d] Result: status=%s  summary=%s",
            step,
            result.get("status"),
            result.get("summary", "")[:120],
        )

        # 7. Merge into state ──────────────────────────────────────────────────
        apply_result(self.state, tool_name, result)
        self.state.record_attempt(
            technique_id=result.get("technique_id", tool_name),
            target=args.get("target_ip") or args.get("dc_ip") or self.state.dc_ip,
            result=result,
            step=step,
        )

        # 8. Post-step goal check ──────────────────────────────────────────────
        if self.state.full_goal_achieved:
            log.info("[step %d] 🎯 GOAL ACHIEVED after tool execution!", step)
            self._record_and_log(step, tool_name, result, response_text)
            self._finalize("goal_achieved")
            return True, result

        # 9. Persist step to run log ───────────────────────────────────────────
        self._record_and_log(step, tool_name, result, response_text)
        return False, result

    # ── helpers ───────────────────────────────────────────────────────────────

    def _record_and_log(
        self,
        step: int,
        tool_name: str,
        result: dict,
        response_text: str,
    ) -> None:
        """Write a structured step record to the JSONL run log."""
        self.logger.write({
            "event":          "step",
            "step":           step,
            "tool":           tool_name,
            "status":         result.get("status"),
            "summary":        result.get("summary", ""),
            "response_text":  response_text,
            "state_snapshot": self.state.to_dict(),
        })

    def _finalize(self, reason: str) -> None:
        """Write the terminal run record."""
        # Ensure state.stop_reason is set for summary display
        self.state.stop_reason = reason
        self.logger.write({
            "event":      "run_end",
            "stop_reason": reason,
            "steps_taken": self.state.step,
            "goal_achieved": self.state.full_goal_achieved,
            "da_confirmed":  self.state.da_credential_confirmed,
            "krbtgt_ready":  self.state.golden_ticket_ready,
            "final_state":   self.state.to_dict(),
        })
        log.info("Run ended — reason=%s  steps=%d", reason, self.state.step)

    def _print_summary(self) -> None:
        """Human-readable terminal summary after the loop exits."""
        s = self.state
        width = 60
        print("\n" + "═" * width)
        print(f"  RUN SUMMARY  [{self.cfg.run_id}]")
        print("═" * width)
        print(f"  Domain      : {s.target_domain}")
        print(f"  DC          : {s.dc_ip}")
        print(f"  Model       : {self.cfg.hf_model_id}")
        print(f"  Steps taken : {s.step} / {s.max_steps}")
        print(f"  Stop reason : {s.stop_reason or 'N/A'}")
        print(f"  DA confirmed: {s.da_credential_confirmed}")
        print(f"  krbtgt hash : {s.golden_ticket_ready}")
        print(f"  GOAL MET    : {s.full_goal_achieved}")
        print("─" * width)
        print("  Techniques completed:")
        for t in s.completed_techniques:
            print(f"    ✓  {t}")
        print("─" * width)
        print("  Credentials in state:")
        for cred in s.credentials.values():
            marker = "★" if cred.privilege_level.value in ("domain_admin", "da_equivalent") else " "
            print(
                f"  {marker} {cred.key:<40} "
                f"priv={cred.privilege_level.value:<14} "
                f"pt={'yes' if cred.plaintext else 'no ':3} "
                f"hash={'yes' if cred.nt_hash else 'no'}"
            )
        print("═" * width)
        print(f"  Run log: {self.logger.path}")
        print("═" * width + "\n")


# ──────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ──────────────────────────────────────────────────────────────────────────────

def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="AEV LLM-driven AD red team agent",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--domain",     required=True, help="Target domain (e.g. LAB.LOCAL)")
    p.add_argument("--dc-ip",      required=True, help="Domain Controller IP")
    p.add_argument("--username",   required=True, help="Seed credential username")
    p.add_argument("--password",   default="",    help="Seed credential plaintext password")
    p.add_argument("--nt-hash",    default=None,  help="Seed credential NT hash (alternative to password)")
    p.add_argument("--max-steps",  type=int, default=30, help="Step budget")
    p.add_argument("--wordlist",   default="/usr/share/wordlists/rockyou.txt", help="Hashcat wordlist path")
    p.add_argument("--model",      default=None,  help="Override HF_MODEL_ID env var")
    p.add_argument("--temperature",type=float, default=0.2, help="LLM temperature")
    p.add_argument("--verbose",    action="store_true", help="Set log level to DEBUG")
    return p


def main() -> None:
    parser = _build_arg_parser()
    args   = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.password and not args.nt_hash:
        parser.error("Provide at least one of --password or --nt-hash")

    cfg = AgentConfig(
        domain=args.domain,
        dc_ip=args.dc_ip,
        username=args.username,
        password=args.password,
        nt_hash=args.nt_hash,
        max_steps=args.max_steps,
        wordlist=args.wordlist,
        hf_model_id=args.model or os.getenv("HF_MODEL_ID", "Qwen/Qwen2.5-72B-Instruct"),
        temperature=args.temperature,
    )

    agent = LLMAgent(cfg)
    final_state = agent.run()

    # Exit 0 on goal_achieved, 1 otherwise
    sys.exit(0 if final_state.full_goal_achieved else 1)


if __name__ == "__main__":
    main()