# AEV Framework — Security Findings Report

> Generated: 2026-08-25 17:05 UTC  
> Run ID: `93b34fc3`  
> Domain: `coficab.lab`  
> Model: `deepseek/deepseek-v4-flash`  

---

## Executive Summary

| Metric | Value |
|--------|-------|
| **Overall Score** | `75.83%` |
| **Goal** | ✅ Full domain compromise achieved |
| **Steps** | 5 / 20 |
| **Stop Reason** | `goal_achieved` |
| **DA Confirmed** | Yes |
| **krbtgt Captured** | Yes ⚠️ |

### Score Breakdown

| Dimension | Score | Weight |
|-----------|-------|--------|
| Technique Coverage | `50.00%` | 35% |
| Step Efficiency | `100.00%` | 25% |
| Stop Reason | `100.00%` | 20% |
| Sysmon Detection | `66.67%` | 20% |
| Parse Failure Penalty | `-0.00%` | — |

### ⚠️ Detection Gaps

The following techniques were executed by the agent but **not detected** by Sysmon:

- **T1003.006** — DCSync (Priority: **CRITICAL**)

---

## Attack Chain

**Step 1** `run_bloodhound` — ✓ success  
  > Collected AD data: 1 computers, 1 domains, 19 containers, 1 ous, 2 gpos, 52 groups, 12 users. 3 Kerberoastable users, 1 

**Step 2** `run_kerberoast` — ✓ success  
  > Kerberoasted 2 account(s): svc-sql, svc-backup. Run hashcat with mode 13100 to crack offline.

**Step 3** `submit_to_hashcat` — ✓ submitted  
  > Submitted job 'job_1e519654' (mode 13100, 2 hash(es), wordlist rockyou.txt) — poll check_cracked('job_1e519654').

**Step 4** `check_cracked` — ✓ cracked  
  > 2 credential(s) recovered for job 'job_1e519654'.

**Step 5** `run_dcsync` — ✓ success  
  > DCSync: dumped 1 hash(es) (1 user accounts, 0 machine accounts). krbtgt hash captured: 70c0bbb8e46092e40477b736f4cad4b6.

---

## Technique Findings

| Technique | Name | Agent Executed | Sysmon Detected | Gap | Priority |
|-----------|------|:--------------:|:---------------:|:---:|----------|
| `T1003.006` | DCSync (OS Credential Dumping) | ✅ | ❌ | ⚠️ | CRITICAL |
| `T1558.003` | Kerberoasting | ✅ | ✅ |  | HIGH |
| `T1558.004` | AS-REP Roasting | — | ✅ |  | HIGH |
| `T1021.002` | Lateral Movement (SMB / PtH) | — | ✅ |  | HIGH |
| `T1087.002` | Domain Account Enumeration (BloodHound) | ✅ | ✅ |  | MEDIUM |

---

## Hardening Recommendations

### CRITICAL — T1003.006: DCSync ⚠️ Detection Gap

**Detection method:** Security 4662 with DS-Replication-* GUIDs  
**Sysmon notes:** CRITICAL DETECTION GAP: DCSync executed but not detected — enable 4662 auditing on domain object with SACL

**Recommended mitigations:**

- Enable SACL auditing on the domain object for replication rights (4662)
- Restrict DS-Replication-Get-Changes-All to Domain Controllers only
- Alert on 4662 from non-DC accounts — any such event is anomalous
- Deploy Privileged Access Workstations (PAW) for DA operations
- Enable Protected Users security group for all privileged accounts

### HIGH — T1558.003: Kerberoasting

**Detection method:** Security 4769 with TicketEncryptionType=0x17 (RC4-HMAC)  
**Sysmon notes:** RC4 TGS requests detected: 2 event(s)

**Recommended mitigations:**

- Enforce AES-only encryption: set msDS-SupportedEncryptionTypes = 0x18 on all service accounts
- Use Managed Service Accounts (gMSA) — 240-char auto-rotated passwords defeat offline cracking
- Alert on RC4 TGS requests to service accounts (4769 + 0x17)
- Rotate service account passwords to 25+ random chars immediately

### MEDIUM — T1087.002: AD Enumeration / BloodHound

**Detection method:** Sysmon PID 1 (process creation) + bulk 4769 TGS requests  
**Sysmon notes:** Bulk TGS requests: 5 events (threshold ≥5)

**Recommended mitigations:**

- Restrict LDAP query permissions — enable LDAP signing & channel binding
- Deploy Credential Guard to protect LSASS
- Alert on >10 TGS requests from a single user within 5 minutes
- Audit BloodHound / SharpHound process names via Sysmon rule

---

## Credentials Harvested

| Account | Privilege | Plaintext | Hash | Source |
|---------|-----------|:---------:|:----:|--------|
| `coficab.lab\aymen` | `user` | ✅ | — | `seed` |
| `coficab.lab\svc-sql` | `user` | ✅ | — | `T1558.003` |
| `coficab.lab\svc-backup` | `domain_admin` | ✅ | — | `T1558.003` |
| `coficab.lab\krbtgt` | `da_equivalent` | — | ✅ | `T1003.006` |

---

*This report was generated automatically by the AEV Framework.*  
*All testing was performed in an isolated lab environment.*
