"""
aev.scoring.log_parser
======================
Parses two log sources:

  1. Agent run JSONL  (runs/*.jsonl)   → RunRecord
  2. Sysmon telemetry (.evtx or .jsonl) → list[SysmonEvent]

Usage
-----
    from aev.scoring.log_parser import parse_run, parse_sysmon_evtx, parse_sysmon_jsonl

    run    = parse_run("runs/340b1c02.jsonl")
    events = parse_sysmon_evtx("/mnt/sysmon/sysmon.evtx",
                               start=run.start_ts, end=run.end_ts)
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


# ─── Data models ──────────────────────────────────────────────────────────────

@dataclass
class StepRecord:
    step:       int
    tool:       str
    status:     str
    summary:    str
    timestamp:  Optional[datetime]
    response_text: str = ""


@dataclass
class CredentialRecord:
    username:        str
    domain:          str
    privilege_level: str
    has_plaintext:   bool
    has_hash:        bool
    source:          str


@dataclass
class RunRecord:
    run_id:               str
    domain:               str
    dc_ip:                str
    model:                str
    steps_taken:          int
    max_steps:            int
    stop_reason:          str
    goal_met:             bool
    da_confirmed:         bool
    krbtgt_captured:      bool
    completed_techniques: list[str]
    credentials:          list[CredentialRecord]
    steps:                list[StepRecord]
    start_ts:             Optional[datetime]
    end_ts:               Optional[datetime]
    parse_failures:       int = 0
    source_path:          str = ""


@dataclass
class SysmonEvent:
    event_id:    int
    timestamp:   datetime
    computer:    str
    raw:         dict = field(default_factory=dict)

    # Convenience accessors — populated from raw where available
    subject_user:   str = ""
    target_user:    str = ""
    service_name:   str = ""
    properties:     str = ""
    object_name:    str = ""
    logon_type:     str = ""
    process_name:   str = ""
    command_line:   str = ""


# ─── Run JSONL parser ─────────────────────────────────────────────────────────

def parse_run(path: str | Path) -> RunRecord:
    """Parse a single agent run JSONL file into a RunRecord."""
    path = Path(path)
    lines = [json.loads(l) for l in path.read_text().splitlines() if l.strip()]

    # Separate event types
    step_events   = [l for l in lines if l.get("event") == "step"]
    summary_event = next((l for l in lines if l.get("event") in ("run_summary", "run_end")), None)
    start_event   = next((l for l in lines if l.get("event") == "run_start"),   None)

    # Timestamps
    start_ts = _parse_ts(start_event.get("_ts") if start_event else None)
    end_ts   = _parse_ts(step_events[-1].get("_ts") if step_events else None)

    # Parse failure count — correction prompt retries logged as warnings
    parse_failures = sum(
        1 for e in step_events
        if "parse_failure" in e.get("event", "") or
           "No <tool_call>" in e.get("response_text", "")
    )

    # Build StepRecord list
    steps: list[StepRecord] = []
    for e in step_events:
        steps.append(StepRecord(
            step=e.get("step", 0),
            tool=e.get("tool", ""),
            status=e.get("status", ""),
            summary=e.get("summary", ""),
            timestamp=_parse_ts(e.get("_ts")),
            response_text=e.get("response_text", ""),
        ))

    # Final state from last step or summary
    final_state: dict = {}
    if summary_event:
        final_state = summary_event.get("final_state", {})
    elif step_events:
        final_state = step_events[-1].get("state_snapshot", {})

    # Credentials
    creds: list[CredentialRecord] = []
    for key, c in (final_state.get("credentials") or {}).items():
        creds.append(CredentialRecord(
            username=c.get("username", ""),
            domain=c.get("domain", ""),
            privilege_level=c.get("privilege_level", "unknown"),
            has_plaintext=bool(c.get("plaintext")),
            has_hash=c.get("has_nt_hash", False),
            source=c.get("source", ""),
        ))

    # Run metadata — fall back to scanning step events
    run_id     = _infer_run_id(path, start_event, step_events)
    stop_reason = final_state.get("stop_reason", "")
    if not stop_reason or stop_reason == "unknown":
        if summary_event and summary_event.get("stop_reason"):
            stop_reason = summary_event["stop_reason"]
    if not stop_reason or stop_reason == "unknown":
        for e in reversed(step_events):
            if "stop_reason" in e:
                stop_reason = e["stop_reason"]
                break
    if not stop_reason:
        stop_reason = "unknown"

    return RunRecord(
        run_id=run_id,
        domain=final_state.get("target_domain", ""),
        dc_ip=final_state.get("dc_ip", ""),
        model=start_event.get("model", "") if start_event else "",
        steps_taken=final_state.get("step", len(steps)),
        max_steps=final_state.get("max_steps", 20),
        stop_reason=stop_reason,
        goal_met=final_state.get("full_goal_achieved", False),
        da_confirmed=final_state.get("da_credential_confirmed", False),
        krbtgt_captured=final_state.get("golden_ticket_ready", False),
        completed_techniques=final_state.get("completed_techniques") or [],
        credentials=creds,
        steps=steps,
        start_ts=start_ts,
        end_ts=end_ts,
        parse_failures=parse_failures,
        source_path=str(path),
    )


def parse_runs_dir(runs_dir: str | Path) -> list[RunRecord]:
    """Parse all *.jsonl files in a directory."""
    runs_dir = Path(runs_dir)
    records = []
    for p in sorted(runs_dir.glob("*.jsonl")):
        try:
            records.append(parse_run(p))
        except Exception as exc:
            log.warning("Failed to parse %s: %s", p, exc)
    return records


# ─── Sysmon parsers ───────────────────────────────────────────────────────────

def parse_sysmon_jsonl(
    path: str | Path,
    start: Optional[datetime] = None,
    end:   Optional[datetime] = None,
) -> list[SysmonEvent]:
    """
    Parse a Sysmon export already converted to JSONL (one JSON object per line).
    Expected keys: EventID, TimeCreated (ISO), Computer, EventData (dict).
    """
    path = Path(path)
    events: list[SysmonEvent] = []

    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            continue

        ts = _parse_ts(
            raw.get("TimeCreated") or
            raw.get("timestamp") or
            raw.get("_ts")
        )
        if ts and start and ts < start:
            continue
        if ts and end and ts > end:
            continue

        ev_data = raw.get("EventData") or raw.get("event_data") or {}
        events.append(_make_sysmon_event(
            event_id=int(raw.get("EventID") or raw.get("event_id") or 0),
            timestamp=ts or datetime.now(timezone.utc),
            computer=raw.get("Computer") or raw.get("computer") or "",
            ev_data=ev_data,
            raw=raw,
        ))

    return events


def parse_sysmon_evtx(
    path: str | Path,
    start: Optional[datetime] = None,
    end:   Optional[datetime] = None,
) -> list[SysmonEvent]:
    """
    Parse a raw Windows .evtx file using python-evtx.
    Install: pip install python-evtx --break-system-packages

    Falls back to parse_sysmon_jsonl if path ends with .jsonl.
    """
    path = Path(path)
    if path.suffix.lower() == ".jsonl":
        return parse_sysmon_jsonl(path, start=start, end=end)

    try:
        import Evtx.Evtx as evtx
        import xml.etree.ElementTree as ET
    except ImportError:
        raise ImportError(
            "python-evtx is required for .evtx parsing: "
            "pip install python-evtx --break-system-packages"
        )

    events: list[SysmonEvent] = []
    NS = "http://schemas.microsoft.com/win/2004/08/events/event"

    with evtx.Evtx(str(path)) as log_file:
        for record in log_file.records():
            try:
                root = ET.fromstring(record.xml())
            except ET.ParseError:
                continue

            sys_el = root.find(f"{{{NS}}}System")
            if sys_el is None:
                continue

            ev_id_el = sys_el.find(f"{{{NS}}}EventID")
            ev_id    = int(ev_id_el.text) if ev_id_el is not None else 0

            time_el = sys_el.find(f"{{{NS}}}TimeCreated")
            ts_str  = time_el.attrib.get("SystemTime") if time_el is not None else None
            ts      = _parse_ts(ts_str)

            if ts and start and ts < start:
                continue
            if ts and end and ts > end:
                continue

            computer_el = sys_el.find(f"{{{NS}}}Computer")
            computer    = computer_el.text if computer_el is not None else ""

            ev_data: dict = {}
            for data_el in root.iter(f"{{{NS}}}Data"):
                name = data_el.attrib.get("Name", "")
                if name:
                    ev_data[name] = data_el.text or ""

            events.append(_make_sysmon_event(
                event_id=ev_id,
                timestamp=ts or datetime.now(timezone.utc),
                computer=computer,
                ev_data=ev_data,
                raw={"EventID": ev_id, "EventData": ev_data},
            ))

    return events


# ─── Internal helpers ─────────────────────────────────────────────────────────

def _make_sysmon_event(
    event_id: int,
    timestamp: datetime,
    computer: str,
    ev_data: dict,
    raw: dict,
) -> SysmonEvent:
    return SysmonEvent(
        event_id=event_id,
        timestamp=timestamp,
        computer=computer,
        raw=raw,
        subject_user=ev_data.get("SubjectUserName") or ev_data.get("TargetUserName") or "",
        target_user=ev_data.get("TargetUserName") or "",
        service_name=ev_data.get("ServiceName") or ev_data.get("TicketOptions") or "",
        properties=ev_data.get("Properties") or ev_data.get("AccessMask") or "",
        object_name=ev_data.get("ObjectName") or "",
        logon_type=str(ev_data.get("LogonType") or ""),
        process_name=ev_data.get("ProcessName") or ev_data.get("Image") or "",
        command_line=ev_data.get("CommandLine") or "",
    )


def _parse_ts(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, AttributeError):
        return None


def _infer_run_id(
    path: Path,
    start_event: Optional[dict],
    step_events: list[dict],
) -> str:
    if start_event and start_event.get("run_id"):
        return start_event["run_id"]
    # try first step's state_snapshot
    if step_events:
        snap = step_events[0].get("state_snapshot") or {}
        if snap.get("run_id"):
            return snap["run_id"]
    return path.stem