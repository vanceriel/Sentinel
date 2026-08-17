# SENTINEL — Incident Investigation Simulator

Simulates cybersecurity incidents and generates logs for hands-on incident response practice. Designed for SOC analysts and incident responders learning investigation workflows.

---

## What It Does

| Component | Purpose |
|-----------|---------|
| **incident_simulator.py** | Generate 60+ realistic security logs across 5 attack phases |
| **log_analyzer.py** | Correlate events, extract IOCs, detect attack patterns |
| **report_generator.py** | Create investigation reports with root cause & remediation |
| **run.py** | Run all three scripts in sequence automatically |

Supports two scenarios: SSH brute-force attacks and malware infections with C2 beaconing.

---

## Quick Start

```bash
# Run everything at once
python run.py
# Choose: 1 (Brute Force) or 2 (Malware) or 3 (Both)

```

Or run individually (options 1 and 2 only):

```bash
# 1. Generate incident logs
python incident_simulator.py
# Choose: 1 (Brute Force) or 2 (Malware)

# 2. Analyze logs
python log_analyzer.py logs/brute_force_attack_TIMESTAMP.json
# or
python log_analyzer.py logs/malware_infection_TIMESTAMP.json

# 3. Generate report
python report_generator.py logs/brute_force_attack_TIMESTAMP.json
# or
python report_generator.py logs/malware_infection_TIMESTAMP.json
```

Replace `TIMESTAMP` with the value generated in step 1 (e.g. `brute_force_attack_20260129_141935.json`).

Output files are saved in the logs/ folder.

---

## Project Structure

```
sentinel/
├── incident_simulator.py    ← Generate incidents
├── log_analyzer.py          ← Analyze & investigate
├── report_generator.py      ← Create reports
├── run.py                   ← Run all three at once
├── .gitignore
├── README.md
└── logs/                    ← Output saved here (auto-created on first run)
    └── .gitkeep
```

Output files generated after running:

```
sentinel/
└── logs/
    ├── brute_force_attack_TIMESTAMP.json
    ├── brute_force_attack_TIMESTAMP_timeline.txt
    ├── brute_force_attack_TIMESTAMP_analysis.txt
    └── brute_force_attack_TIMESTAMP_INVESTIGATION_REPORT.txt
```

---

## Requirements

- Python 3.7+
- No external dependencies (uses Python standard library only)

---

## Features

**Incident Simulator:**
- Multi-source log generation (firewall, auth, endpoint, network)
- Realistic timestamps, IPs, severity levels
- Two complete attack scenarios with phase progression

**Log Analyzer:**
- Pattern recognition (failed login clustering, C2 beacons, data transfers)
- IOC extraction (malicious IPs, file hashes, registry keys, processes)
- IP profiling and severity distribution analysis
- Interactive query mode: search by IP, time range, severity, keyword
- Automated analysis report generation

**Report Generator:**
- Executive summary with impact assessment
- Chronological attack timeline with phase identification
- Root cause analysis with MITRE ATT&CK technique mapping
- IOC section for threat intelligence sharing
- Three-tier remediation plan (immediate/short-term/long-term)

---

## Example Output

**Attack Timeline:**
```
[1] 2026-01-29T12:19:35Z - RECONNAISSANCE
    Attacker: 106.80.137.147
    Target: 192.168.40.197:22
    Action: Port scanning (SYN packets)

[2] 2026-01-29T12:24:35Z - BRUTE FORCE ATTACK
    56 failed SSH login attempts over 56 minutes
    Target user: admin
    Pattern: Sequential password guessing

[3] 2026-01-29T13:20:35Z - SUCCESSFUL BREACH
    Accepted password for admin from 106.80.137.147
    Severity: CRITICAL

[4] 2026-01-29T13:27:35Z - POST-COMPROMISE
    Commands executed: sudo su, cat /etc/passwd, netstat -an
    Severity: CRITICAL

[5] 2026-01-29T13:40:35Z - DATA EXFILTRATION
    5.2MB transferred to attacker infrastructure
    Severity: CRITICAL
```

**Analysis Findings:**
- 56 failed login attempts from single IP
- 1 successful breach detected
- 5 post-compromise enumeration commands
- 5.2MB data exfiltration
- IOCs: 1 attacker IP, 1 malware hash, 3 suspicious file paths

---

## Incident Scenarios

### Brute Force Attack
**Duration:** ~80 minutes | **Events:** 66 logs

1. **Reconnaissance** — Port scanning for open SSH
2. **Brute Force** — 45-75 failed password attempts
3. **Successful Breach** — Valid credentials compromised
4. **Post-Compromise** — System enumeration, privilege escalation attempts
5. **Data Exfiltration** — Large outbound transfer to attacker

**Detection Focus:** Multiple failed logins, unusual post-login commands, abnormal data transfers

### Malware Infection
**Duration:** ~75 minutes | **Events:** 30 logs

1. **Initial Infection** — Phishing email with malicious attachment
2. **Execution** — Malware runs, establishes persistence via registry
3. **C2 Communication** — Regular beaconing to command & control server
4. **Lateral Movement** — SMB connections to internal systems
5. **Credential Theft** — LSASS memory access for credential dumping
6. **Data Staging** — 50MB archive created in temp directory
7. **Exfiltration** — Data transferred to C2 infrastructure

**Detection Focus:** Email attachment detonation, process tree analysis, C2 beacon patterns, LSASS access

---

## Investigation Workflow

**Step 1: Initial Review** (5 min)
- Run log analyzer to get overview
- Review IP statistics and severity distribution
- Identify affected systems

**Step 2: Deep Dive** (20 min)
- Build chronological timeline
- Identify attack phases
- Track attacker progression

**Step 3: Extract IOCs** (10 min)
- Malicious IPs for blocking
- File hashes for detection
- Suspicious processes
- Registry keys

**Step 4: Root Cause Analysis** (15 min)
- Determine initial access method
- Identify security control failures
- Map to MITRE ATT&CK techniques
- Assess business impact

**Step 5: Remediation Plan** (15 min)
- Immediate containment actions
- Short-term security fixes
- Long-term improvements

---

## Log Structure

Each log entry contains:

```json
{
  "timestamp": "2026-01-29T12:19:35Z",
  "source_ip": "106.80.137.147",
  "destination_ip": "192.168.40.197",
  "action": "Failed login",
  "severity": "WARNING",
  "log_type": "auth",
  "message": "Failed password for admin from 106.80.137.147"
}
```

**Log Types:** firewall, auth, endpoint, network, email  
**Severity Levels:** INFO, WARNING, HIGH, CRITICAL

---

## Interactive Mode

```bash
python log_analyzer.py logs/brute_force_attack_TIMESTAMP.json --interactive
```

**Options:**
1. Search by IP address — Find all activities from/to specific IP
2. Filter by severity — Focus on critical events only
3. Time range query — Investigate specific time windows
4. Keyword search — Hunt for specific terms
5. Show critical events — Quick view of most important findings

---

## Common Workflows

**Quick run (recommended):**
```bash
python run.py
```
Time: ~5 minutes

**Full investigation with interactive mode:**
```bash
python incident_simulator.py
python log_analyzer.py logs/brute_force_attack_TIMESTAMP.json --interactive
python report_generator.py logs/brute_force_attack_TIMESTAMP.json
```
Time: ~30 minutes

**Both scenarios:**
```bash
python incident_simulator.py
# Input: 3 (generates both)
python log_analyzer.py logs/brute_force_attack_TIMESTAMP.json
python log_analyzer.py logs/malware_infection_TIMESTAMP.json
python report_generator.py logs/brute_force_attack_TIMESTAMP.json
python report_generator.py logs/malware_infection_TIMESTAMP.json
```
Time: ~45 minutes
