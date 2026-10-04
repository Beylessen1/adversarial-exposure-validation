"""
schema.py — State and result contracts for the autonomous AD red team agent.

Design principles
-----------------
1.  Explicit over inferred.  The agent should never have to guess whether it
    has domain admin or whether kerberoasting has been tried — the state
    answers these questions directly.

2.  Forward-only updates.  Every tool result is distilled into a *delta* and
    merged into the master AgentState via ``apply_result()``.  Nothing is
    deleted; facts only accumulate.

3.  Serialisable.  All types resolve to plain dicts/lists/primitives so the
    state can be JSON-dumped and injected wholesale into a prompt.

4.  Privilege levels form a strict partial order that gates tool availability:
        unknown < user < local_admin < domain_admin / da_equivalent
    A credential object always carries its known privilege level so the agent
    does not have to re-derive it.

"""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# ──────────────────────────────────────────────────────────────────────────────
# 1.  Privilege levels
# ──────────────────────────────────────────────────────────────────────────────

class PrivilegeLevel(str, Enum):
    """Strict ordering: unknown < user < local_admin < domain_admin < da_equivalent."""
    UNKNOWN        = "unknown"
    USER           = "user"
    LOCAL_ADMIN    = "local_admin"
    DOMAIN_ADMIN   = "domain_admin"
    DA_EQUIVALENT  = "da_equivalent"   # krbtgt hash captured → golden ticket possible


_PRIV_ORDER: Dict[PrivilegeLevel, int] = {
    PrivilegeLevel.UNKNOWN:       0,
    PrivilegeLevel.USER:          1,
    PrivilegeLevel.LOCAL_ADMIN:   2,
    PrivilegeLevel.DOMAIN_ADMIN:  3,
    PrivilegeLevel.DA_EQUIVALENT: 4,
}


def privilege_gte(a: PrivilegeLevel, b: PrivilegeLevel) -> bool:
    """Return True if privilege level *a* is at least as powerful as *b*."""
    return _PRIV_ORDER[a] >= _PRIV_ORDER[b]


# ──────────────────────────────────────────────────────────────────────────────
# 2.  Credential record
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class Credential:
    """
    A single confirmed credential.  At least one of ``plaintext`` or
    ``nt_hash`` must be set for the credential to be usable by any tool.

    ``privilege_level`` represents the *highest confirmed* privilege for this
    account across the entire domain (not just on one machine).

    ``hash_type`` is structural ("asrep" | "tgs" | "ntlm") so hashcat mode
    selection does not need to parse note strings.
    """
    username:          str
    domain:            str
    plaintext:         Optional[str]    = None
    nt_hash:           Optional[str]    = None   # 32-char hex NT hash
    lm_hash:           Optional[str]    = None   # almost always empty LM
    privilege_level:   PrivilegeLevel   = PrivilegeLevel.UNKNOWN
    source_technique:  Optional[str]    = None   # MITRE ID that produced this
    cracked_from_hash: Optional[str]    = None   # original hash string if cracked offline
    hash_type:         Optional[str]    = None   # "asrep" | "tgs" | "ntlm"
    notes:             List[str]        = field(default_factory=list)

    # ── convenience properties ──────────────────────────────────────────────

    @property
    def usable(self) -> bool:
        """True if there is enough material to attempt authentication."""
        return bool(self.plaintext or self.nt_hash)

    @property
    def key(self) -> str:
        """Stable identity key: domain\\username (lowercase)."""
        return f"{self.domain.lower()}\\{self.username.lower()}"

    @property
    def is_crackable(self) -> bool:
        """
        True if this credential has a captured offline hash that has not yet
        been cracked.  Relies on hash_type being set by apply_result.

        Includes ntlm hashes (from secrets_dump / dcsync) in addition to
        asrep / tgs hashes so that cracked NTLM accounts also flow through
        the hashcat pipeline.
        """
        return self.hash_type in ("asrep", "tgs", "ntlm") and not self.plaintext

    def to_dict(self) -> dict:
        return {
            "username":         self.username,
            "domain":           self.domain,
            "plaintext":        self.plaintext,
            "nt_hash_prefix":   (self.nt_hash[:12] + "...") if self.nt_hash else None,
            "has_nt_hash":      self.nt_hash is not None,
            "privilege_level":  self.privilege_level.value,
            "source_technique": self.source_technique,
            "hash_type":        self.hash_type,
            "is_crackable":     self.is_crackable,
            "notes":            self.notes,
            "usable":           self.usable,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Credential":
        d = dict(d)
        d["privilege_level"] = PrivilegeLevel(d.get("privilege_level", "unknown"))
        d.pop("usable", None)
        d.pop("nt_hash_prefix", None)
        d.pop("has_nt_hash", None)
        d.pop("is_crackable", None)
        return cls(**d)


# ──────────────────────────────────────────────────────────────────────────────
# 3.  Host / target record
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class HostRecord:
    """
    Everything the agent knows about a single reachable machine.
    Known roles: "dc", "workstation", "server", "unknown".
    """
    ip:                       str
    hostname:                 Optional[str]  = None
    domain:                   Optional[str]  = None
    roles:                    List[str]      = field(default_factory=list)
    os_info:                  Optional[str]  = None
    smb_signing_enabled:      Optional[bool] = None
    unconstrained_delegation: bool           = False
    open_services:            List[str]      = field(default_factory=list)
    local_admin_creds:        List[str]      = field(default_factory=list)  # credential keys
    compromised:              bool           = False
    notes:                    List[str]      = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "ip":                       self.ip,
            "hostname":                 self.hostname,
            "domain":                   self.domain,
            "roles":                    self.roles,
            "os_info":                  self.os_info,
            "smb_signing_enabled":      self.smb_signing_enabled,
            "unconstrained_delegation": self.unconstrained_delegation,
            "open_services":            self.open_services,
            "local_admin_creds":        self.local_admin_creds,
            "compromised":              self.compromised,
            "notes":                    self.notes,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "HostRecord":
        return cls(**d)


# ──────────────────────────────────────────────────────────────────────────────
# 4.  Enumeration artifacts
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class EnumerationArtifacts:
    """Structured facts derived from BloodHound / LDAP enumeration."""
    bloodhound_json_paths:              List[str]       = field(default_factory=list)
    kerberoastable_users:               List[str]       = field(default_factory=list)
    asrep_vulnerable_users:             List[str]       = field(default_factory=list)
    admincount_users:                   List[str]       = field(default_factory=list)
    unconstrained_delegation_computers: List[str]       = field(default_factory=list)
    domain_controllers:                 List[str]       = field(default_factory=list)  # IPs
    object_counts:                      Dict[str, int]  = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "bloodhound_json_paths":               self.bloodhound_json_paths,
            "kerberoastable_users":                self.kerberoastable_users,
            "asrep_vulnerable_users":              self.asrep_vulnerable_users,
            "admincount_users":                    self.admincount_users,
            "unconstrained_delegation_computers":  self.unconstrained_delegation_computers,
            "domain_controllers":                  self.domain_controllers,
            "object_counts":                       self.object_counts,
        }


# ──────────────────────────────────────────────────────────────────────────────
# 5.  Hashcat job tracker
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class HashcatJob:
    """Tracks a single async hashcat session submitted via hashcat.py."""
    session:      str
    pid:          Optional[int]
    mode:         int
    hash_count:   int
    wordlist:     str
    submitted_at: float                      # time.monotonic() at submission
    status:       str        = "pending"     # pending | cracked | exhausted | cancelled | error
    cracked:      List[Dict] = field(default_factory=list)
    # cracked entry: {"account": str, "hash": str, "plaintext": str}

    def to_dict(self) -> dict:
        return {
            "session":    self.session,
            "pid":        self.pid,
            "mode":       self.mode,
            "hash_count": self.hash_count,
            "wordlist":   self.wordlist,
            "status":     self.status,
            "cracked":    self.cracked,
        }


# ──────────────────────────────────────────────────────────────────────────────
# 6.  Attempt tracker (dead-end detection)
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class TechniqueAttempt:
    """
    Records each time the agent tried a technique.
    technique_id should always be a MITRE ID (e.g. "T1558.003").
    tool_used is the Python function name called (e.g. "run_kerberoast").
    Keeping both prevents the key-mismatch bug where fail_counts mixed IDs
    and tool names depending on whether the wrapper emitted technique_id.
    """
    technique_id: str
    target:       str
    status:       str    # "success" | "error" | "timeout" | "exhausted"
    summary:      str
    step_number:  int
    tool_used:    str    # actual tool function name


# ──────────────────────────────────────────────────────────────────────────────
# 7.  Master agent state
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class AgentState:
    """
    The single source of truth the agent reads before each decision and that
    every tool result updates after execution.

    Goal flags:
        da_credential_confirmed  — a DA-or-above usable credential exists
        golden_ticket_ready      — krbtgt NT hash is captured
        full_goal_achieved       — BOTH of the above (the actual stop condition)

    Only full_goal_achieved triggers goal_achieved stop. The other two flags
    are diagnostic signals surfaced in the prompt.
    """

    # ── mission parameters (set once at startup) ──────────────────────────────
    target_domain: str = ""
    dc_ip:         str = ""
    wordlist_path: str = "/usr/share/wordlists/rockyou.txt"
    max_steps:     int = 30

    # ── accumulated knowledge ─────────────────────────────────────────────────
    credentials:  Dict[str, Credential]  = field(default_factory=dict)
    hosts:        Dict[str, HostRecord]  = field(default_factory=dict)
    enumeration:  EnumerationArtifacts   = field(default_factory=EnumerationArtifacts)

    # ── progress tracking ─────────────────────────────────────────────────────
    completed_techniques: List[str]           = field(default_factory=list)
    attempts:             List[TechniqueAttempt] = field(default_factory=list)
    hashcat_jobs:         Dict[str, HashcatJob]  = field(default_factory=dict)

    # ── goal flags (set exclusively by _refresh_goal_flags) ──────────────────
    da_credential_confirmed: bool = False
    golden_ticket_ready:     bool = False
    full_goal_achieved:      bool = False

    # ── loop control ──────────────────────────────────────────────────────────
    step:        int           = 0
    stop_reason: Optional[str] = None

    # ── rolling summary window ────────────────────────────────────────────────
    recent_summaries: List[str] = field(default_factory=list)
    SUMMARY_WINDOW:   int       = 8

    # ── convenience accessors ─────────────────────────────────────────────────

    def best_credential(self, min_priv: PrivilegeLevel = PrivilegeLevel.USER) -> Optional[Credential]:
        """
        Return the highest-privilege usable credential at or above *min_priv*,
        preferring plaintext over hash-only (some tools need plaintext).
        """
        candidates = [
            c for c in self.credentials.values()
            if c.usable and privilege_gte(c.privilege_level, min_priv)
        ]
        if not candidates:
            return None
        return sorted(
            candidates,
            key=lambda c: (_PRIV_ORDER[c.privilege_level], 1 if c.plaintext else 0),
            reverse=True,
        )[0]

    def has_da(self) -> bool:
        """True if any usable credential is DA or DA-equivalent."""
        return any(
            privilege_gte(c.privilege_level, PrivilegeLevel.DOMAIN_ADMIN)
            for c in self.credentials.values()
            if c.usable
        )

    def has_krbtgt_hash(self) -> bool:
        """True if the krbtgt NT hash is captured."""
        key = f"{self.target_domain.lower()}\\krbtgt"
        cred = self.credentials.get(key)
        return cred is not None and cred.nt_hash is not None

    def technique_tried(self, technique_id: str, target: Optional[str] = None) -> bool:
        return any(
            a.technique_id == technique_id and (target is None or a.target == target)
            for a in self.attempts
        )

    def technique_succeeded(self, technique_id: str) -> bool:
        return technique_id in self.completed_techniques

    def failed_attempts_for(self, technique_id: str) -> int:
        return sum(
            1 for a in self.attempts
            if a.technique_id == technique_id and a.status != "success"
        )

    def dc_host(self) -> Optional[HostRecord]:
        """Return the first host tagged as 'dc', or None."""
        for h in self.hosts.values():
            if "dc" in h.roles:
                return h
        return None

    def get_crackable_hashes(self) -> List[Credential]:
        """Return all credentials with uncracked captured hashes."""
        return [c for c in self.credentials.values() if c.is_crackable]

    def get_hashcat_mode(self) -> int:
        """
        Determine the appropriate hashcat mode from available uncracked hashes.
        AS-REP (18200) takes priority if mixed; returns 0 if nothing crackable.
        """
        crackable = self.get_crackable_hashes()
        if any(c.hash_type == "asrep" for c in crackable):
            return 18200
        if any(c.hash_type == "tgs" for c in crackable):
            return 13100
        return 0

    # ── serialisation ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        """
        Compact, prompt-ready representation.
        NT hashes are truncated to first 12 chars to save tokens.
        Plaintext passwords are included in full — tools need them.
        """
        def _cred_summary(c: Credential) -> dict:
            return {
                "username":        c.username,
                "domain":          c.domain,
                "plaintext":       c.plaintext,
                "nt_hash_prefix":  (c.nt_hash[:12] + "...") if c.nt_hash else None,
                "has_nt_hash":     c.nt_hash is not None,
                "privilege_level": c.privilege_level.value,
                "source":          c.source_technique,
                "hash_type":       c.hash_type,
                "is_crackable":    c.is_crackable,
            }

        def _host_summary(h: HostRecord) -> dict:
            return {
                "ip":                       h.ip,
                "hostname":                 h.hostname,
                "domain":                   h.domain,
                "roles":                    h.roles,
                "smb_signing":              h.smb_signing_enabled,
                "unconstrained_delegation": h.unconstrained_delegation,
                "compromised":              h.compromised,
                "local_admin_creds":        h.local_admin_creds,
            }

        pending_hashcat = [
            j.to_dict() for j in self.hashcat_jobs.values()
            if j.status == "pending"
        ]

        return {
            "target_domain":          self.target_domain,
            "dc_ip":                  self.dc_ip,
            "step":                   self.step,
            "max_steps":              self.max_steps,
            "da_credential_confirmed": self.da_credential_confirmed,
            "golden_ticket_ready":    self.golden_ticket_ready,
            "full_goal_achieved":     self.full_goal_achieved,
            "credentials":            {k: _cred_summary(c) for k, c in self.credentials.items()},
            "hosts":                  {ip: _host_summary(h) for ip, h in self.hosts.items()},
            "enumeration":            self.enumeration.to_dict(),
            "completed_techniques":   self.completed_techniques,
            "failed_attempts": [
                {"technique_id": a.technique_id, "target": a.target, "summary": a.summary}
                for a in self.attempts if a.status != "success"
            ],
            "pending_hashcat_jobs":   pending_hashcat,
            "recent_summaries":       self.recent_summaries[-self.SUMMARY_WINDOW:],
        }

    # ── state update helpers ──────────────────────────────────────────────────

    def record_attempt(self, technique_id: str, target: str, result: dict, step: int) -> None:
        """Append an attempt record regardless of success/failure."""
        
        # normalize "submitted" so it's treated as success everywhere
        effective_status = "success" if result.get("status") == "submitted" else result.get("status", "error")
        
        attempt = TechniqueAttempt(
            technique_id=technique_id,
            target=target,
            status=effective_status,          # ← was: result.get("status", "error")
            summary=result.get("summary", ""),
            step_number=step,
            tool_used=result.get("tool_name", technique_id),
        )
        self.attempts.append(attempt)
        if effective_status == "success":     # ← was: result.get("status") == "success"
            tid = result.get("technique_id") or technique_id
            if tid and tid not in self.completed_techniques:
                self.completed_techniques.append(tid)
        summary = result.get("summary", "")
        if summary:
            self.recent_summaries.append(f"[Step {step}] {summary}")

    def add_credential(self, cred: Credential) -> None:
        """Upsert a credential, upgrading privilege if the new entry is higher."""
        existing = self.credentials.get(cred.key)
        if existing is None:
            self.credentials[cred.key] = cred
        else:
            if _PRIV_ORDER[cred.privilege_level] > _PRIV_ORDER[existing.privilege_level]:
                existing.privilege_level = cred.privilege_level
            if cred.plaintext and not existing.plaintext:
                existing.plaintext = cred.plaintext
            if cred.nt_hash and not existing.nt_hash:
                existing.nt_hash = cred.nt_hash
            if cred.hash_type and not existing.hash_type:
                existing.hash_type = cred.hash_type
            for note in cred.notes:
                if note not in existing.notes:
                    existing.notes.append(note)
        self._refresh_goal_flags()

    def add_host(self, host: HostRecord) -> None:
        """Upsert a host record, merging new information."""
        existing = self.hosts.get(host.ip)
        if existing is None:
            self.hosts[host.ip] = host
            return
        if host.hostname:
            existing.hostname = host.hostname
        if host.domain:
            existing.domain = host.domain
        for role in host.roles:
            if role not in existing.roles:
                existing.roles.append(role)
        if host.smb_signing_enabled is not None:
            existing.smb_signing_enabled = host.smb_signing_enabled
        if host.unconstrained_delegation:
            existing.unconstrained_delegation = True
        if host.compromised:
            existing.compromised = True
        for svc in host.open_services:
            if svc not in existing.open_services:
                existing.open_services.append(svc)
        for ckey in host.local_admin_creds:
            if ckey not in existing.local_admin_creds:
                existing.local_admin_creds.append(ckey)

    def _refresh_goal_flags(self) -> None:
        """
        Single authoritative setter for all three goal flags.
        Called after every credential mutation — never set flags directly elsewhere.
        """
        self.da_credential_confirmed = self.has_da()
        self.golden_ticket_ready     = self.has_krbtgt_hash()
        self.full_goal_achieved      = self.da_credential_confirmed and self.golden_ticket_ready


# ──────────────────────────────────────────────────────────────────────────────
# 8.  Result ingestion
# ──────────────────────────────────────────────────────────────────────────────

def apply_result(state: AgentState, tool_name: str, result: dict) -> AgentState:
    """
    Merge a tool result dict into *state*.  Returns the (mutated) state.

    Every tool result must include:
        status       : "success" | "error" | "timeout" | "exhausted"
        technique_id : MITRE ATT&CK ID (e.g. "T1558.003")  — always emit this
        summary      : human-readable one-liner
        data         : tool-specific payload dict (may be empty)

    Normalise tool_name aliases (run_bloodhound == bloodhound) so the agent
    loop can call either form without breaking ingestion.
    """


    

    technique_id = result.get("technique_id") or tool_name
    status       = result.get("status", "error")
    data         = result.get("data") or {}

    # ── bloodhound ────────────────────────────────────────────────────────────
    if tool_name in ("bloodhound", "run_bloodhound"):
        if status == "success":
            ea = state.enumeration

            for u in (data.get("kerberoastable_users") or []):
                if u not in ea.kerberoastable_users:
                    ea.kerberoastable_users.append(u)
            for u in (data.get("admincount_users") or []):
                if u not in ea.admincount_users:
                    ea.admincount_users.append(u)
            for c in (data.get("unconstrained_delegation_computers") or []):
                if c not in ea.unconstrained_delegation_computers:
                    ea.unconstrained_delegation_computers.append(c)
            ea.object_counts.update(data.get("counts") or {})

            # DC hosts — wrapper may return list-of-dicts or list-of-strings.
            # list-of-dicts: [{"ip": "10.0.0.1", "hostname": "DC01"}]
            # list-of-strings: ["10.0.0.1"]  (single-DC lab fallback)
            raw_dcs = data.get("domain_controllers") or []
            for entry in raw_dcs:
                if isinstance(entry, dict):
                    dc_ip_val  = entry.get("ip", "")
                    dc_hostname = entry.get("hostname")
                else:
                    dc_ip_val  = entry
                    dc_hostname = data.get("dc_hostname")  # single-DC compat
                if not dc_ip_val:
                    continue
                if dc_ip_val not in ea.domain_controllers:
                    ea.domain_controllers.append(dc_ip_val)
                state.add_host(HostRecord(
                    ip=dc_ip_val,
                    domain=state.target_domain,
                    roles=["dc"],
                    hostname=dc_hostname,
                ))

            # Always ensure the configured dc_ip is in hosts — wrapper may
            # not enumerate it explicitly in single-DC labs.
            if state.dc_ip and state.dc_ip not in state.hosts:
                state.add_host(HostRecord(
                    ip=state.dc_ip,
                    domain=state.target_domain,
                    roles=["dc"],
                ))

    # ── asrep_roast ───────────────────────────────────────────────────────────
    elif tool_name in ("asrep_roast", "run_asrep_roast"):
        if status == "success":
            for h in (data.get("hashes") or []):
                state.add_credential(Credential(
                    username=h["account"],
                    domain=state.target_domain,
                    privilege_level=PrivilegeLevel.UNKNOWN,
                    source_technique=technique_id,
                    hash_type="asrep",
                    # Store FULL hash string — available_actions reads it for hashcat suggested_args
                    notes=[f"AS-REP hash captured (mode 18200): {h['hash']}"],
                ))
            for u in (data.get("vulnerable_users") or []):
                if u not in state.enumeration.asrep_vulnerable_users:
                    state.enumeration.asrep_vulnerable_users.append(u)

    # ── kerberoast ────────────────────────────────────────────────────────────
    elif tool_name in ("kerberoast", "run_kerberoast"):
        if status == "success":
            for h in (data.get("hashes") or []):
                state.add_credential(Credential(
                    username=h["account"],
                    domain=state.target_domain,
                    privilege_level=PrivilegeLevel.UNKNOWN,
                    source_technique=technique_id,
                    hash_type="tgs",
                    # Store FULL hash string — available_actions reads it for hashcat suggested_args
                    notes=[f"TGS hash captured (mode 13100): {h['hash']}"],
                ))

    # ── submit_to_hashcat ─────────────────────────────────────────────────────
    elif tool_name == "submit_to_hashcat":
        if status in ("success", "submitted"):
            session = data.get("session")
            if session:
                state.hashcat_jobs[session] = HashcatJob(
                    session=session,
                    pid=data.get("pid"),
                    mode=data.get("mode", 0),
                    hash_count=data.get("hash_count", 0),
                    wordlist=data.get("wordlist", state.wordlist_path),
                    # Default to current monotonic time if wrapper omits it.
                    submitted_at=data.get("submitted_at", time.monotonic()),
                    status="pending",
                )

    # ── check_cracked ─────────────────────────────────────────────────────────
    elif tool_name in ("check_cracked", "hashcat"):
        session = data.get("session")
        if session and session in state.hashcat_jobs:
            job = state.hashcat_jobs[session]
            job.status  = status
            job.cracked = data.get("cracked", [])
            for entry in job.cracked:          # ← must be indented here, inside the if
                account   = entry.get("account") or entry.get("username", "")
                plaintext = entry.get("plaintext", "")
                if not account or not plaintext:
                    continue

                name_lower = account.lower()
                admincount_names = [u.lower().split("@")[0] for u in state.enumeration.admincount_users]
                inferred_priv = (
                    PrivilegeLevel.DOMAIN_ADMIN
                    if name_lower in admincount_names
                    else PrivilegeLevel.USER
                )

                key = f"{state.target_domain.lower()}\\{name_lower}"
                cred = state.credentials.get(key)
                if cred:
                    cred.plaintext = plaintext
                    if _PRIV_ORDER[inferred_priv] > _PRIV_ORDER[cred.privilege_level]:
                        cred.privilege_level = inferred_priv
                    state._refresh_goal_flags()
                else:
                    state.add_credential(Credential(
                        username=account,
                        domain=state.target_domain,
                        plaintext=plaintext,
                        privilege_level=inferred_priv,
                        source_technique="T1110.002",
                    ))

    # ── secrets_dump ──────────────────────────────────────────────────────────
    elif tool_name in ("secrets_dump", "run_secrets_dump"):
        if status == "success":
            for h in (data.get("sam_hashes") or []) + (data.get("domain_hashes") or []):
                priv = PrivilegeLevel.UNKNOWN
                if h.get("rid") == 500 or "administrator" in h.get("username", "").lower():
                    priv = PrivilegeLevel.LOCAL_ADMIN
                state.add_credential(Credential(
                    username=h["username"],
                    domain=h.get("domain") or state.target_domain,
                    nt_hash=h["nt_hash"],
                    lm_hash=h.get("lm_hash"),
                    privilege_level=priv,
                    source_technique=technique_id,
                    hash_type="ntlm",
                ))

    # ── dcsync ────────────────────────────────────────────────────────────────
    elif tool_name in ("dcsync", "run_dcsync"):
        if status == "success":
            for h in (data.get("all_hashes") or []):
                name_lower = h.get("username", "").lower()
                rid        = h.get("rid", -1)
                if rid == 502 or name_lower == "krbtgt":
                    priv = PrivilegeLevel.DA_EQUIVALENT
                elif rid == 500 or name_lower == "administrator":
                    priv = PrivilegeLevel.DOMAIN_ADMIN
                elif h.get("is_machine_account"):
                    priv = PrivilegeLevel.UNKNOWN
                else:
                    priv = PrivilegeLevel.USER
                state.add_credential(Credential(
                    username=h["username"],
                    domain=h.get("domain") or state.target_domain,
                    nt_hash=h["nt_hash"],
                    lm_hash=h.get("lm_hash"),
                    privilege_level=priv,
                    source_technique=technique_id,
                    hash_type="ntlm",
                ))

    # ── lateral_movement ──────────────────────────────────────────────────────
    elif tool_name in ("lateral_movement", "run_lateral_movement"):
        if status == "success":
            target_ip      = data.get("target_ip", "")
            credential_key = data.get("credential_key")
            host = HostRecord(
                ip=target_ip,
                hostname=data.get("target_hostname"),
                domain=data.get("target_domain"),
                smb_signing_enabled=data.get("smb_signing_enabled"),
                compromised=data.get("command_executed", False),
                roles=[],
            )
            if data.get("local_admin") and credential_key:
                host.roles.append("workstation")
                if credential_key not in host.local_admin_creds:
                    host.local_admin_creds.append(credential_key)
                # Promote credential privilege level in-place.
                cred = state.credentials.get(credential_key)
                if cred and _PRIV_ORDER[cred.privilege_level] < _PRIV_ORDER[PrivilegeLevel.LOCAL_ADMIN]:
                    cred.privilege_level = PrivilegeLevel.LOCAL_ADMIN
                    state._refresh_goal_flags()
            state.add_host(host)

    # ── stop_attack ───────────────────────────────────────────────────────────
    elif tool_name == "stop_attack":
        # reason arrives in result directly (not nested under data).
        # Fall back to data["reason"] for wrappers that nest it.
        reason = result.get("reason") or data.get("reason", "agent_abort")
        state.stop_reason = reason
        # Do NOT set full_goal_achieved here — only _refresh_goal_flags may
        # set goal flags, based on actual credential state.

    return state


# ──────────────────────────────────────────────────────────────────────────────
# 9.  Available-actions computation
# ──────────────────────────────────────────────────────────────────────────────

def available_actions(state: AgentState) -> List[Dict[str, Any]]:
    """
    Return all actions the agent may call right now, conditioned on state.
    Only actions with precondition_met=True are shown in the user message.

    IMPORTANT: stop_attack is always included with precondition_met=True, but
    should_stop() excludes it when computing dead-end detection so that the
    presence of stop_attack alone never masks a genuine dead end.
    """
    actions: List[Dict[str, Any]] = []
    cred_user = state.best_credential(PrivilegeLevel.USER)
    cred_la   = state.best_credential(PrivilegeLevel.LOCAL_ADMIN)
    cred_da   = state.best_credential(PrivilegeLevel.DOMAIN_ADMIN)

    # ── BloodHound ────────────────────────────────────────────────────────────
    bh_done = state.technique_succeeded("T1087.002")
    actions.append({
        "tool":             "run_bloodhound",
        "technique":        "T1087.002",
        "description":      "Enumerate AD structure: users, computers, SPNs, delegation, paths to DA.",
        "precondition_met": bool(cred_user and not bh_done),
        "blocked_reason":   (
            "already completed" if bh_done
            else "need at least one valid domain user credential"
        ) if not (cred_user and not bh_done) else None,
        "suggested_args": {
            "domain":   state.target_domain,
            "username": cred_user.username if cred_user else None,
            "password": cred_user.plaintext if cred_user else None,
            "dc_ip":    state.dc_ip,
        },
    })

    # ── AS-REP Roasting ───────────────────────────────────────────────────────
    asrep_done = state.technique_succeeded("T1558.004")
    actions.append({
        "tool":             "run_asrep_roast",
        "technique":        "T1558.004",
        "description":      "Capture TGT hashes for users with pre-auth disabled (no creds needed if user list available).",
        "precondition_met": not asrep_done,
        "blocked_reason":   "already completed" if asrep_done else None,
        "suggested_args": {
            "domain":   state.target_domain,
            "dc_ip":    state.dc_ip,
            # username/password enable authenticated mode (more results).
            # Omit users_file — None is the default and confuses the model.
            **({"username": cred_user.username, "password": cred_user.plaintext}
               if cred_user and cred_user.plaintext else {}),
        },
    })

    # ── Kerberoasting ─────────────────────────────────────────────────────────
    kerb_done       = state.technique_succeeded("T1558.003")
    has_spn_targets = bool(state.enumeration.kerberoastable_users)
    # Skip if every kerberoastable account already has a plaintext password —
    # re-roasting would produce hashes we can't do anything with.
    spn_usernames      = {u.lower() for u in state.enumeration.kerberoastable_users}
    cracked_spn_count  = sum(
        1 for c in state.credentials.values()
        if c.username.lower() in spn_usernames and c.plaintext
    )
    all_spns_cracked = has_spn_targets and cracked_spn_count >= len(spn_usernames)
    actions.append({
        "tool":             "run_kerberoast",
        "technique":        "T1558.003",
        "description":      "Request TGS tickets for SPN accounts and capture hashes for offline cracking.",
        "precondition_met": bool(cred_user and not kerb_done and has_spn_targets and not all_spns_cracked),
        "blocked_reason":   (
            "already completed" if kerb_done
            else "all SPN accounts already cracked — no value in re-roasting" if all_spns_cracked
            else "need at least one valid domain user credential" if not cred_user
            else "no SPN targets found — run bloodhound first"
        ) if not (cred_user and not kerb_done and has_spn_targets and not all_spns_cracked) else None,
        "suggested_args": {
            "domain":   state.target_domain,
            "username": cred_user.username if cred_user else None,
            "password": cred_user.plaintext if cred_user else None,
            "dc_ip":    state.dc_ip,
        },
        "context": (
            f"{len(state.enumeration.kerberoastable_users)} SPN target(s) known."
            if has_spn_targets else "Run BloodHound first to identify SPN targets."
        ),
    })

    # ── Hashcat submit ────────────────────────────────────────────────────────
    crackable = state.get_crackable_hashes()
    # Pull the actual hash strings from credential notes so the model has
    # them ready to paste — it cannot derive them from the truncated to_dict.
    hash_strings = []
    for cred in crackable:
        for note in cred.notes:
            # Notes look like: "TGS hash captured (mode 13100): $krb5tgs$23$..."
            # Only store notes that contain a full hash (not truncated with "...")
            if ": " in note:
                raw = note.split(": ", 1)[1]
                if not raw.endswith("..."):
                    hash_strings.append(raw)
    actions.append({
        "tool":             "submit_to_hashcat",
        "technique":        "T1110.002",
        "description":      "Launch offline password cracking for captured hashes (async).",
        "precondition_met": bool(crackable),
        "blocked_reason":   None if crackable else "no uncracked hashes in state yet",
        "suggested_args": {
            "hashes":   [f"<{len(crackable)} hash(es) auto-loaded from state>"],
            "mode":     state.get_hashcat_mode(),
            "wordlist": state.wordlist_path,
        },
        "context": f"{len(crackable)} uncracked hash(es) in state. Mode {state.get_hashcat_mode()} auto-selected.",
    })

    # ── Hashcat check ─────────────────────────────────────────────────────────
    pending_jobs = [j for j in state.hashcat_jobs.values() if j.status == "pending"]
    actions.append({
        "tool":             "check_cracked",
        "technique":        "T1110.002",
        "description":      "Poll a running hashcat job for cracked passwords.",
        "precondition_met": bool(pending_jobs),
        "blocked_reason":   None if pending_jobs else "no pending hashcat jobs",
        "suggested_args": {
            "session": pending_jobs[0].session if pending_jobs else None,
        },
    })

    # ── Secrets dump ──────────────────────────────────────────────────────────
    sd_done    = state.technique_succeeded("T1003.002")
    la_targets = [h for h in state.hosts.values() if h.local_admin_creds and not h.compromised]
    actions.append({
        "tool":             "run_secrets_dump",
        "technique":        "T1003.002",
        "description":      "Dump SAM/LSA secrets from a target where we have local admin.",
        "precondition_met": bool(cred_la and la_targets and not sd_done),
        "blocked_reason":   (
            "already completed" if sd_done
            else "need local admin credential" if not cred_la
            else "no known targets with local admin access"
        ) if not (cred_la and la_targets and not sd_done) else None,
        "suggested_args": {
            "domain":    state.target_domain,
            "username":  cred_la.username if cred_la else None,
            "target_ip": la_targets[0].ip if la_targets else None,
            "password":  cred_la.plaintext if cred_la else None,
            "hashes":    f":{cred_la.nt_hash}" if cred_la and cred_la.nt_hash and not cred_la.plaintext else None,
        },
    })

    # ── DCSync ────────────────────────────────────────────────────────────────
    dc_done = state.technique_succeeded("T1003.006")
    dc_host = state.dc_host()
    actions.append({
        "tool":             "run_dcsync",
        "technique":        "T1003.006",
        "description":      "Replicate NTDS credentials from DC (requires Domain Admin or Replicating Directory Changes).",
        "precondition_met": bool((cred_da or state.has_da()) and dc_host and not dc_done),
        "blocked_reason":   (
            "already completed" if dc_done
            else "need Domain Admin credential" if not (cred_da or state.has_da())
            else "DC not yet in hosts — run bloodhound first"
        ) if not ((cred_da or state.has_da()) and dc_host and not dc_done) else None,
        "suggested_args": {
            "domain":      state.target_domain,
            "username":    cred_da.username if cred_da else None,
            "dc_ip":       dc_host.ip if dc_host else state.dc_ip,
            "password":    cred_da.plaintext if cred_da else None,
            "hashes":      f":{cred_da.nt_hash}" if cred_da and cred_da.nt_hash and not cred_da.plaintext else None,
            "target_user": "krbtgt",
        },
    })

    # ── Lateral movement ──────────────────────────────────────────────────────
    lm_targets = [h for h in state.hosts.values() if not h.compromised and h.ip != state.dc_ip]
    actions.append({
        "tool":             "run_lateral_movement",
        "technique":        "T1021.002",
        "description":      "Authenticate to a target via SMB/WinRM/WMI and optionally execute a command.",
        "precondition_met": bool(cred_user and lm_targets),
        "blocked_reason":   (
            "need at least one valid credential" if not cred_user
            else "no lateral movement targets identified yet"
        ) if not (cred_user and lm_targets) else None,
        "suggested_args": {
            "target_ip": lm_targets[0].ip if lm_targets else None,
            "username":  cred_user.username if cred_user else None,
            "password":  cred_user.plaintext if cred_user else None,
            "nt_hash":   cred_user.nt_hash if cred_user and not cred_user.plaintext else None,
            "command":   "whoami /groups",
        },
    })

    # ── stop_attack (always present, meta-action) ─────────────────────────────
    # NOTE: should_stop() excludes this entry from dead-end detection.
    actions.append({
        "tool":             "stop_attack",
        "technique":        "N/A",
        "description":      "Terminate the attack loop with a specific reason.",
        "precondition_met": True,
        "blocked_reason":   None,
        "suggested_args": {
            "reason": "goal_achieved" if state.full_goal_achieved else "dead_end",
        },
    })

    return actions


# ──────────────────────────────────────────────────────────────────────────────
# 10.  Stopping conditions
# ──────────────────────────────────────────────────────────────────────────────

def should_stop(state: AgentState) -> tuple[bool, str]:
    """
    Return (stop: bool, reason: str).  Called at the top of each agent loop
    iteration before the LLM is queried.

    Order: goal detection → hard limits → dead-end detection.
    """
    # Full goal: DA + krbtgt both confirmed.
    if state.full_goal_achieved:
        return True, "goal_achieved"

    # Hard step limit.
    if state.step >= state.max_steps:
        return True, "max_steps"

    # Dead-end detection: exclude stop_attack from the count — it is a
    # meta-action and its presence must never mask a genuine dead end.
    actions  = available_actions(state)
    unblocked = [
        a for a in actions
        if a["precondition_met"] and a["tool"] != "stop_attack"
    ]
    if not unblocked:
        return True, "dead_end"

    # Repeated failure: same tool failed ≥ 3 times.
    # Count by tool_used (always the Python function name) rather than
    # technique_id, which can vary across wrappers and cause two failures for
    # the same real tool to be spread across different counter keys.
    # Exclude schema/dispatch errors — these are self-correcting mistakes, not
    # genuine dead ends.
    IGNORABLE_TECHNIQUE_IDS = {"ARG_ERROR", "PRECONDITION_BLOCKED", "RUNTIME_ERROR", "UNKNOWN"}
    fail_counts = Counter(
        a.tool_used for a in state.attempts
        if a.status != "success" and a.technique_id not in IGNORABLE_TECHNIQUE_IDS
    )
    if any(count >= 3 for count in fail_counts.values()):
        worst = max(fail_counts, key=fail_counts.get)
        return True, f"dead_end:repeated_failure:{worst}"

    return False, ""