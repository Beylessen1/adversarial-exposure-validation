<div align="center">

```
 █████╗ ███████╗██╗   ██╗
██╔══██╗██╔════╝██║   ██║
███████║█████╗  ██║   ██║
██╔══██║██╔══╝  ╚██╗ ██╔╝
██║  ██║███████╗ ╚████╔╝ 
╚═╝  ╚═╝╚══════╝  ╚═══╝  
```

**Adversarial Exposure Validation**

*An AI-driven red teaming framework that attacks Active Directory and scores its own detection coverage — autonomously.*

[![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-E3001B?style=flat-square)](https://attack.mitre.org)
[![DeepSeek](https://img.shields.io/badge/LLM-DeepSeek_V4_Flash-4F46E5?style=flat-square)](https://deepseek.com)
[![License](https://img.shields.io/badge/License-MIT-22C55E?style=flat-square)](LICENSE)

</div>

---

## What is AEV?

AEV is a Breach and Attack Simulation (BAS) framework with a twist: instead of running a hardcoded playbook, an LLM-driven agent **reasons its way** through an Active Directory attack chain — deciding which technique to use next based on what it knows about the domain state. After the run, a separate scoring engine reads Sysmon telemetry independently and reports which attacks your detection stack would have actually caught.

The question it answers isn't *"did the attack succeed?"* — it's **"which attacks succeeded silently?"**

---

## Architecture

AEV is two independent pipelines connected by a single JSONL run log.

```
┌─────────────────────────────────────────────────────────────┐
│                      PIPELINE 1: AGENT                      │
│                                                             │
│  Low-priv cred  →  [ ReAct Loop ]  →  run_id.jsonl         │
│                      ↕ LLM proposes                         │
│                      ↕ Code validates & executes            │
│                      ↕ State updates                        │
└──────────────────────────┬──────────────────────────────────┘
                           │  shared artifact: run log
┌──────────────────────────▼──────────────────────────────────┐
│                     PIPELINE 2: SCORER                      │
│                                                             │
│  run_id.jsonl  +  Sysmon .evtx  →  findings report + score │
│                                                             │
│  The scorer has zero visibility into the agent's reasoning. │
│  It reads telemetry. It checks. It reports.                 │
└─────────────────────────────────────────────────────────────┘
```

### Agent — Three Layers

| Layer | File | Role |
|---|---|---|
| **State Machine** | `schema.py` | `AgentState` knowledge graph — credentials, privilege levels, preconditions |
| **LLM Interface** | `prompts.py` | Translates state → prompt, parses response → structured tool call |
| **Outer Loop** | `llm_agent.py` | Owns the ReAct cycle, JSONL logging, termination logic |

**Core principle:** The LLM proposes. Deterministic code validates, executes, updates state, and decides when the run ends.

### Tool Library — ATT&CK-Mapped

| Technique | Tool | File |
|---|---|---|
| T1087.002 | BloodHound Enumeration | `tools/enum_bloodhound.py` |
| T1558.003 | Kerberoasting | `tools/kerberoast.py` |
| T1558.004 | AS-REP Roasting | `tools/asrep_roast.py` |
| — | Hashcat Cracking | `tools/hashcat.py` |
| T1003.006 | DCSync | `tools/dcsync.py` |
| T1003.002 | SAM/LSA Secrets Dump | `tools/secrets_dump.py` |
| T1021.002 | Lateral Movement (SMB/PtH) | `tools/lateral_movement.py` |

### Scorer — Three Modules

| Module | Role |
|---|---|
| `log_parser.py` | Normalises run JSONL + Sysmon `.evtx` into structured objects |
| `detection_rules.py` | Maps each ATT&CK technique to its expected event signature |
| `report_generator.py` | Produces a Markdown findings report + JSON score summary |

---

## Attack Chain

```
              [BloodHound Enum]
                     │
          ┌──────────┴──────────┐
    [Kerberoasting]        [AS-REP Roasting]
          │                     │
          └──────────┬──────────┘
                [Hashcat Crack]
                     │
              ┌──────┴──────┐
           DA found?     Not yet
              │              │
          [DCSync]    [Lateral Movement]
              │              │
        Domain Owned    [Secrets Dump]
                             │
                         [Hashcat…]
```

The agent reasons through this tree. The hardcoded runner (`runner_hardcoded.py`) follows it in fixed order and serves as ground truth for tool validation.

---

## Reference Run — `7cff605d`

The agent completed domain compromise in **5 steps** against a live AD lab (`coficab.lab`), skipping AS-REP Roasting (no vulnerable accounts in state) and lateral movement (krbtgt hash captured before it was needed).

```
Step 1  T1087.002   BloodHound    → 3 Kerberoastable users, 1 pre-auth disabled
Step 2  T1558.003   Kerberoast    → 2 TGS hashes captured (svc-sql, svc-backup)
Step 3  —           Hashcat       → job submitted (mode 13100, rockyou.txt)
Step 4  —           check_cracked → 2 credentials recovered
Step 5  T1003.006   DCSync        → krbtgt NT hash captured ★ GOAL ACHIEVED
```

**Model:** `deepseek/deepseek-v4-flash` — maintained reasoning quality across the full chain with no mid-run degradation.

### Detection Coverage Report

| Technique | Name | Agent Executed | Sysmon Detected | Gap | Priority |
|---|---|:---:|:---:|:---:|---|
| T1003.006 | DCSync | ✅ | ❌ | ⚠️ | **CRITICAL** |
| T1558.003 | Kerberoasting | ✅ | ✅ | — | HIGH |
| T1558.004 | AS-REP Roasting | — | ✅ | — | HIGH |
| T1021.002 | Lateral Movement (SMB/PtH) | — | ✅ | — | HIGH |
| T1087.002 | BloodHound Enumeration | ✅ | ✅ | — | MEDIUM |

**Overall score: 75.83%**

The DCSync miss is the headline: `secretsdump` fired DS-Replication-Get-Changes-All and captured the krbtgt hash. Security Event 4662 was never generated because the domain object had no SACL configured to audit replication rights — a silent gap in the vast majority of real AD environments.

---

## Repo Structure

```
adversarial-exposure-validation/
│
├── aev/
│   ├── agent/
│   │   ├── schema.py           # AgentState — credential graph, privilege levels
│   │   ├── prompts.py          # LLM interface — state→prompt, response→tool call
│   │   ├── llm_agent.py        # ReAct outer loop, logging, termination
│   │   └── runner_hardcoded.py # Fixed-order runner for ground-truth validation
│   │
│   ├── tools/                  # ATT&CK-mapped tool wrappers
│   │   ├── enum_bloodhound.py
│   │   ├── kerberoast.py
│   │   ├── asrep_roast.py
│   │   ├── hashcat.py
│   │   ├── dcsync.py
│   │   ├── secrets_dump.py
│   │   └── lateral_movement.py
│   │
│   ├── scoring/
│   │   ├── log_parser.py       # Normalise run log + Sysmon evtx
│   │   ├── detection_rules.py  # Per-technique detection checks
│   │   ├── report_generator.py # Markdown report + JSON score
│   │   └── score_run.py        # Entry point
│   │
│   └── logs/
│       ├── sysmon.evtx / .jsonl
│       └── security.evtx / .jsonl
│
├── runs/                       # JSONL run logs (one file per run_id)
├── scores/                     # JSON score summaries
└── docs/
    └── findings_report.md      # Reference run findings
```

---

## Running the Agent

```bash
# LLM agent — autonomous attack chain
python3 -m aev.agent.llm_agent \
  --domain coficab.lab \
  --dc-ip 192.168.56.10 \
  --username aymen \
  --password 'P@ssw0rd2026!' \
  --max-steps 20

# Hardcoded runner — deterministic ground truth
python3 -m aev.agent.runner_hardcoded

# Score a completed run
python3 -m aev.scoring.score_run runs/7cff605d.jsonl
```

---

## Why Not LangChain?

Three reasons:

1. **Auditability** — every decision in the attack chain needs to be traceable. A high-level agent abstraction delegates part of that control flow to the framework.
2. **Tool contract** — each tool represents a security-sensitive ATT&CK technique with strict preconditions. That policy needs to stay independent of the LLM and the orchestration layer.
3. **Separation of responsibility** — the LLM proposes actions; it does not decide whether they're allowed, whether a privilege was obtained, or whether the run should terminate.

The JSONL run log is load-bearing: it is the sole bridge between the agent and the scorer, and it makes every run independently auditable.

---

## Blog Series

This project is documented in a three-part series:

| Part | Title | Link |
|---|---|---|
| 1 | Building my AD HomeLab | [→ Read](https://beylessen1.github.io/Blog/2026/08/06/Building-my-AD-HomeLab/) |
| 2 | Building an Agentic Red Teamer | [→ Read](https://beylessen1.github.io/Blog/2026/09/09/Building-an-Agentic-Red-Teamer-Internship-Docs-2/) |
| 3 | Agentic Adversarial Exposure Validation | [→ Read](https://beylessen1.github.io/Blog/2026/09/14/Agentic-Adversarial-Exposure-Validation-Internship-Docs-3/) |

---

## What's Next

- **4662 SACL fix** — enable replication auditing on the domain object, re-run, confirm DCSync detection closes the gap
- **LangGraph migration** — native state graph checkpointing for long-running chains; the security logic stays ours, the runtime gets more robust
- **Evasion research** — the interesting question isn't whether the agent can compromise the domain, it's whether it can do so quietly enough that the detection rules fail

---

<div align="center">

Built during a summer internship at COFICAB Tunisie · by [Beylessen Jendoubi](https://beylessen1.github.io/Blog)

</div>
