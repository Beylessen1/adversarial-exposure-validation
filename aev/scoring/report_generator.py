"""
aev.scoring.report_generator
=============================
Generates the final AEV findings report from a corpus of RunScore objects.

Outputs:
  - Markdown report  (docs/findings_report.md)
  - JSON summary     (scores/<run_id>_score.json  or  scores/corpus_summary.json)
  - Console table    (via generate_console_table)

Usage
-----
Single run:
    from aev.scoring.report_generator import generate_run_report
    md = generate_run_report(run_score, run_record)
    Path("docs/findings_report.md").write_text(md)

Corpus:
    from aev.scoring.report_generator import generate_corpus_report
    md = generate_corpus_report(run_scores)
"""

from __future__ import annotations

import json
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .detection_rules import DetectionResult, RunScore
from .log_parser import RunRecord


# ─── Hardening recommendations ────────────────────────────────────────────────

HARDENING: dict[str, dict] = {
    "T1087.002": {
        "title":       "AD Enumeration / BloodHound",
        "detectable":  "Sysmon PID 1 (process creation) + bulk 4769 TGS requests",
        "mitigations": [
            "Restrict LDAP query permissions — enable LDAP signing & channel binding",
            "Deploy Credential Guard to protect LSASS",
            "Alert on >10 TGS requests from a single user within 5 minutes",
            "Audit BloodHound / SharpHound process names via Sysmon rule",
        ],
        "hardening_priority": "MEDIUM",
    },
    "T1558.003": {
        "title":       "Kerberoasting",
        "detectable":  "Security 4769 with TicketEncryptionType=0x17 (RC4-HMAC)",
        "mitigations": [
            "Enforce AES-only encryption: set msDS-SupportedEncryptionTypes = 0x18 on all service accounts",
            "Use Managed Service Accounts (gMSA) — 240-char auto-rotated passwords defeat offline cracking",
            "Alert on RC4 TGS requests to service accounts (4769 + 0x17)",
            "Rotate service account passwords to 25+ random chars immediately",
        ],
        "hardening_priority": "HIGH",
    },
    "T1558.004": {
        "title":       "AS-REP Roasting",
        "detectable":  "Security 4768 with PreAuthType=0",
        "mitigations": [
            "Enable pre-authentication on all accounts (remove UF_DONT_REQUIRE_PREAUTH)",
            "Alert on 4768 events with PreAuthType=0",
        ],
        "hardening_priority": "HIGH",
    },
    "T1003.006": {
        "title":       "DCSync",
        "detectable":  "Security 4662 with DS-Replication-* GUIDs",
        "mitigations": [
            "Enable SACL auditing on the domain object for replication rights (4662)",
            "Restrict DS-Replication-Get-Changes-All to Domain Controllers only",
            "Alert on 4662 from non-DC accounts — any such event is anomalous",
            "Deploy Privileged Access Workstations (PAW) for DA operations",
            "Enable Protected Users security group for all privileged accounts",
        ],
        "hardening_priority": "CRITICAL",
    },
    "T1021.002": {
        "title":       "SMB Lateral Movement / Pass-the-Hash",
        "detectable":  "Security 4624 (LogonType=3/9) + 4648",
        "mitigations": [
            "Enable Local Administrator Password Solution (LAPS)",
            "Block SMB between workstations (host firewall — no peer-to-peer 445)",
            "Alert on network logons (type 3) from service accounts",
            "Enforce Credential Guard to prevent NTLM hash extraction",
        ],
        "hardening_priority": "HIGH",
    },
}

PRIORITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


# ─── Single run report ────────────────────────────────────────────────────────

def generate_run_report(
    score: RunScore,
    run: Optional[RunRecord] = None,
) -> str:
    """Generate a Markdown findings report for a single run."""
    lines: list[str] = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines += [
        "# AEV Framework — Security Findings Report",
        "",
        f"> Generated: {now}  ",
        f"> Run ID: `{score.run_id}`  ",
        f"> Domain: `{run.domain if run else 'N/A'}`  ",
        f"> Model: `{run.model if run else 'N/A'}`  ",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
    ]

    goal_str = "✅ Full domain compromise achieved" if score.goal_met else "⚠️ Goal not achieved"
    lines += [
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| **Overall Score** | `{score.total_score:.2%}` |",
        f"| **Goal** | {goal_str} |",
        f"| **Steps** | {score.steps_taken} / {score.max_steps} |",
        f"| **Stop Reason** | `{score.stop_reason}` |",
        f"| **DA Confirmed** | {'Yes' if run and run.da_confirmed else 'No'} |",
        f"| **krbtgt Captured** | {'Yes ⚠️' if run and run.krbtgt_captured else 'No'} |",
        "",
        "### Score Breakdown",
        "",
        f"| Dimension | Score | Weight |",
        f"|-----------|-------|--------|",
        f"| Technique Coverage | `{score.coverage_score:.2%}` | 35% |",
        f"| Step Efficiency | `{score.efficiency_score:.2%}` | 25% |",
        f"| Stop Reason | `{score.stop_score:.2%}` | 20% |",
        f"| Sysmon Detection | `{score.sysmon_score:.2%}` | 20% |",
        f"| Parse Failure Penalty | `-{score.parse_failure_penalty:.2%}` | — |",
        "",
    ]

    # Detection gaps callout
    gaps = score.detection_gap_techniques
    if gaps:
        lines += [
            "### ⚠️ Detection Gaps",
            "",
            "The following techniques were executed by the agent but **not detected** by Sysmon:",
            "",
        ]
        for tid in gaps:
            h = HARDENING.get(tid, {})
            lines.append(f"- **{tid}** — {h.get('title', tid)} "
                         f"(Priority: **{h.get('hardening_priority', 'UNKNOWN')}**)")
        lines.append("")

    # Attack chain
    lines += [
        "---",
        "",
        "## Attack Chain",
        "",
    ]
    if run:
        for step in run.steps:
            status_icon = "✓" if step.status in ("success", "submitted", "cracked") else "✗"
            lines.append(
                f"**Step {step.step}** `{step.tool}` — {status_icon} {step.status}  "
            )
            if step.summary:
                lines.append(f"  > {step.summary[:120]}")
            lines.append("")

    # Technique findings table
    lines += [
        "---",
        "",
        "## Technique Findings",
        "",
        "| Technique | Name | Agent Executed | Sysmon Detected | Gap | Priority |",
        "|-----------|------|:--------------:|:---------------:|:---:|----------|",
    ]
    sorted_results = sorted(
        score.detection_results,
        key=lambda r: PRIORITY_ORDER.get(
            HARDENING.get(r.technique_id, {}).get("hardening_priority", "LOW"), 3
        ),
    )
    for r in sorted_results:
        h = HARDENING.get(r.technique_id, {})
        exec_icon = "✅" if r.agent_executed else "—"
        det_icon  = "✅" if r.sysmon_detected else ("❌" if r.agent_executed else "—")
        gap_icon  = "⚠️" if r.detection_gap else ""
        priority  = h.get("hardening_priority", "—")
        lines.append(
            f"| `{r.technique_id}` | {r.technique_name} | {exec_icon} | {det_icon} | {gap_icon} | {priority} |"
        )
    lines.append("")

    # Hardening recommendations
    lines += [
        "---",
        "",
        "## Hardening Recommendations",
        "",
    ]
    executed_ids = {r.technique_id for r in score.detection_results if r.agent_executed}
    prioritised  = sorted(
        executed_ids,
        key=lambda tid: PRIORITY_ORDER.get(
            HARDENING.get(tid, {}).get("hardening_priority", "LOW"), 3
        ),
    )
    for tid in prioritised:
        h = HARDENING.get(tid, {})
        if not h:
            continue
        r = next((x for x in score.detection_results if x.technique_id == tid), None)
        gap_label = " ⚠️ Detection Gap" if (r and r.detection_gap) else ""
        lines += [
            f"### {h['hardening_priority']} — {tid}: {h['title']}{gap_label}",
            "",
            f"**Detection method:** {h['detectable']}  ",
            f"**Sysmon notes:** {r.notes if r else '—'}",
            "",
            "**Recommended mitigations:**",
            "",
        ]
        for m in h["mitigations"]:
            lines.append(f"- {m}")
        lines.append("")

    # Credentials harvested
    if run and run.credentials:
        lines += [
            "---",
            "",
            "## Credentials Harvested",
            "",
            "| Account | Privilege | Plaintext | Hash | Source |",
            "|---------|-----------|:---------:|:----:|--------|",
        ]
        for c in run.credentials:
            pt   = "✅" if c.has_plaintext else "—"
            hash_ = "✅" if c.has_hash    else "—"
            lines.append(
                f"| `{c.domain}\\{c.username}` | `{c.privilege_level}` | {pt} | {hash_} | `{c.source}` |"
            )
        lines.append("")

    lines += [
        "---",
        "",
        "*This report was generated automatically by the AEV Framework.*  ",
        "*All testing was performed in an isolated lab environment.*",
        "",
    ]

    return "\n".join(lines)


# ─── Corpus report ────────────────────────────────────────────────────────────

def generate_corpus_report(scores: list[RunScore]) -> str:
    """Generate a statistical summary report across multiple runs."""
    if not scores:
        return "# AEV Corpus Report\n\nNo runs to report.\n"

    total_scores  = [s.total_score for s in scores]
    goal_met_runs = [s for s in scores if s.goal_met]
    stop_counter  = Counter(s.stop_reason for s in scores)

    # Per-technique detection rate
    tech_exec:  dict[str, int] = defaultdict(int)
    tech_det:   dict[str, int] = defaultdict(int)
    for s in scores:
        for r in s.detection_results:
            if r.agent_executed:
                tech_exec[r.technique_id] += 1
                if r.sysmon_detected:
                    tech_det[r.technique_id] += 1

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines: list[str] = [
        "# AEV Framework — Corpus Analysis Report",
        "",
        f"> Generated: {now}  ",
        f"> Total runs analysed: **{len(scores)}**",
        "",
        "---",
        "",
        "## Corpus Statistics",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Runs | {len(scores)} |",
        f"| Goal achieved | {len(goal_met_runs)} ({len(goal_met_runs)/len(scores):.0%}) |",
        f"| Mean score | `{statistics.mean(total_scores):.3f}` |",
        f"| Median score | `{statistics.median(total_scores):.3f}` |",
        f"| Std dev | `{statistics.stdev(total_scores):.3f}`" if len(scores) > 1 else f"| Std dev | N/A |",
        f"| Min / Max | `{min(total_scores):.3f}` / `{max(total_scores):.3f}` |",
        "",
        "### Stop Reason Distribution",
        "",
        "| Stop Reason | Count | % |",
        "|-------------|-------|---|",
    ]
    for reason, count in stop_counter.most_common():
        lines.append(f"| `{reason}` | {count} | {count/len(scores):.0%} |")

    lines += [
        "",
        "### Per-Technique Detection Rates",
        "",
        "| Technique | Executions | Detections | Detection Rate |",
        "|-----------|:----------:|:----------:|:--------------:|",
    ]
    for tid in sorted(tech_exec, key=lambda t: PRIORITY_ORDER.get(
        HARDENING.get(t, {}).get("hardening_priority", "LOW"), 3
    )):
        exec_n = tech_exec[tid]
        det_n  = tech_det[tid]
        rate   = det_n / exec_n if exec_n else 0.0
        h      = HARDENING.get(tid, {})
        name   = h.get("title", tid)
        lines.append(f"| `{tid}` {name} | {exec_n} | {det_n} | `{rate:.0%}` |")

    lines += ["", "---", ""]
    return "\n".join(lines)


# ─── JSON export ──────────────────────────────────────────────────────────────

def export_score_json(score: RunScore, output_path: str | Path) -> None:
    """Write a single RunScore to a JSON file."""
    Path(output_path).write_text(
        json.dumps(score.summary_dict(), indent=2)
    )


def export_corpus_json(scores: list[RunScore], output_path: str | Path) -> None:
    """Write all RunScores to a JSON file."""
    Path(output_path).write_text(
        json.dumps([s.summary_dict() for s in scores], indent=2)
    )


# ─── Console table ────────────────────────────────────────────────────────────

def generate_console_table(score: RunScore) -> str:
    """Return a compact terminal-friendly summary string."""
    gap_str = ", ".join(score.detection_gap_techniques) or "none"
    return (
        f"\n{'═'*60}\n"
        f"  SCORE SUMMARY  [{score.run_id}]\n"
        f"{'═'*60}\n"
        f"  Total Score    : {score.total_score:.2%}\n"
        f"  Goal Met       : {'YES ✓' if score.goal_met else 'NO ✗'}\n"
        f"  Steps          : {score.steps_taken} / {score.max_steps}\n"
        f"  Stop Reason    : {score.stop_reason}\n"
        f"{'─'*60}\n"
        f"  Coverage       : {score.coverage_score:.2%}\n"
        f"  Efficiency     : {score.efficiency_score:.2%}\n"
        f"  Stop Score     : {score.stop_score:.2%}\n"
        f"  Sysmon Score   : {score.sysmon_score:.2%}\n"
        f"  Parse Penalty  : -{score.parse_failure_penalty:.2%}\n"
        f"{'─'*60}\n"
        f"  Detection Gaps : {gap_str}\n"
        f"{'═'*60}\n"
    )