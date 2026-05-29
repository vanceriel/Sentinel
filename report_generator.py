#!/usr/bin/env python3
"""
Incident Investigation Report Template Generator
Creates professional investigation reports from analysis results
"""

import json
import sys
from datetime import datetime
from typing import Dict, List

class ReportGenerator:
    def __init__(self, log_file: str, analysis_file: str = None):
        self.log_file = log_file
        self.analysis_file = analysis_file or log_file.replace('.json', '_analysis.txt')
        self.report_data = {}
        
    def load_data(self):
        """Load log and analysis data"""
        with open(self.log_file, 'r') as f:
            self.logs = json.load(f)
        
        try:
            with open(self.analysis_file, 'r') as f:
                self.analysis = f.read()
        except FileNotFoundError:
            self.analysis = "Analysis file not found. Please run log_analyzer.py first."
    
    def generate_executive_summary(self, incident_type: str, severity: str) -> str:
        """Generate executive summary section"""
        summary = f"""
EXECUTIVE SUMMARY
{'=' * 80}

Incident Type: {incident_type}
Severity Level: {severity}
Date of Incident: {self.logs[0].get('timestamp', 'Unknown')[:10]}
Total Events Logged: {len(self.logs)}

INCIDENT OVERVIEW:
This report documents a {incident_type.lower()} that was detected and analyzed.
The incident involved multiple attack phases and resulted in {severity.lower()} 
severity findings requiring immediate attention and remediation.

IMPACT ASSESSMENT:
- Affected Systems: {self._count_affected_systems()}
- Attack Duration: {self._calculate_duration()}
- Data Potentially Compromised: {self._assess_data_impact()}

IMMEDIATE ACTIONS TAKEN:
1. Incident containment initiated
2. Affected systems isolated
3. Comprehensive log analysis performed
4. IOCs extracted for threat hunting
5. Remediation plan developed
"""
        return summary
    
    def _count_affected_systems(self) -> str:
        """Count unique affected systems"""
        systems = set()
        for log in self.logs:
            if 'destination_ip' in log:
                systems.add(log['destination_ip'])
            if 'host' in log:
                systems.add(log['host'])
        return f"{len(systems)} system(s)"
    
    def _calculate_duration(self) -> str:
        """Calculate incident duration"""
        if not self.logs:
            return "Unknown"
        first_time = self.logs[0].get('timestamp', '')
        last_time = self.logs[-1].get('timestamp', '')
        return f"From {first_time} to {last_time}"
    
    def _assess_data_impact(self) -> str:
        """Assess data compromise impact"""
        exfil_logs = [log for log in self.logs if 'transfer' in log.get('action', '').lower()]
        if exfil_logs:
            total_bytes = sum(log.get('bytes_transferred', 0) for log in exfil_logs)
            return f"~{total_bytes / (1024*1024):.2f} MB potentially exfiltrated"
        return "None detected"
    
    def generate_timeline_section(self) -> str:
        """Generate detailed timeline section"""
        timeline = f"""
DETAILED INCIDENT TIMELINE
{'=' * 80}

The following timeline reconstructs the attack sequence based on log analysis:
"""
        
        phases = self._identify_attack_phases()
        for phase_name, events in phases.items():
            timeline += f"\n\n{phase_name}\n{'-' * 80}\n"
            for event in events:
                timeline += f"\n[{event.get('timestamp')}]\n"
                timeline += f"  Action: {event.get('action')}\n"
                timeline += f"  Severity: {event.get('severity')}\n"
                if 'source_ip' in event:
                    timeline += f"  Source: {event.get('source_ip')}\n"
                if 'destination_ip' in event:
                    timeline += f"  Target: {event.get('destination_ip')}\n"
                if 'message' in event:
                    timeline += f"  Details: {event.get('message')}\n"
        
        return timeline
    
    def _identify_attack_phases(self) -> Dict[str, List]:
        """Categorize logs into attack phases"""
        phases = {
            "PHASE 1: RECONNAISSANCE & INITIAL ACCESS": [],
            "PHASE 2: PERSISTENCE & PRIVILEGE ESCALATION": [],
            "PHASE 3: LATERAL MOVEMENT & DISCOVERY": [],
            "PHASE 4: COLLECTION & EXFILTRATION": []
        }
        
        for log in self.logs[:5]:  # First few events
            phases["PHASE 1: RECONNAISSANCE & INITIAL ACCESS"].append(log)
        
        for log in self.logs:
            action = log.get('action', '').lower()
            if 'persistence' in action or 'registry' in action or 'escalation' in action:
                phases["PHASE 2: PERSISTENCE & PRIVILEGE ESCALATION"].append(log)
            elif 'lateral' in action or 'smb' in str(log).lower() or 'discovery' in action:
                phases["PHASE 3: LATERAL MOVEMENT & DISCOVERY"].append(log)
            elif 'transfer' in action or 'exfiltration' in action:
                phases["PHASE 4: COLLECTION & EXFILTRATION"].append(log)
        
        return {k: v for k, v in phases.items() if v}  # Only return non-empty phases
    
    def generate_root_cause_analysis(self) -> str:
        """Generate root cause analysis section"""
        rca = f"""
ROOT CAUSE ANALYSIS
{'=' * 80}

INITIAL ACCESS VECTOR:
{self._identify_access_vector()}

SECURITY CONTROL FAILURES:
{self._identify_control_failures()}

VULNERABILITIES EXPLOITED:
{self._identify_vulnerabilities()}

ATTACK TECHNIQUES (MITRE ATT&CK):
{self._map_mitre_attack()}

CONTRIBUTING FACTORS:
1. Inadequate monitoring and alerting capabilities
2. Delayed incident detection and response
3. Insufficient access controls and authentication mechanisms
4. Lack of network segmentation
5. Missing or outdated security patches
"""
        return rca
    
    def _identify_access_vector(self) -> str:
        """Identify how attacker gained initial access"""
        if not self.logs:
            return "Unable to determine from available logs"
        
        first_critical = next((log for log in self.logs 
                              if log.get('severity') == 'CRITICAL'), self.logs[0])
        
        action = first_critical.get('action', '').lower()
        if 'login' in action:
            return f"Successful brute force attack via SSH from {first_critical.get('source_ip')}"
        elif 'email' in first_critical.get('log_type', ''):
            return f"Phishing email with malicious attachment ({first_critical.get('attachment', 'unknown')})"
        else:
            return f"Initial access via: {first_critical.get('action')}"
    
    def _identify_control_failures(self) -> str:
        """Identify which security controls failed"""
        failures = []
        
        if any('failed login' in log.get('action', '').lower() for log in self.logs):
            failures.append("- No account lockout policy after multiple failed login attempts")
            failures.append("- Weak password policy allowed brute force success")
            failures.append("- Multi-factor authentication (MFA) not enforced")
        
        if any('email' in log.get('log_type', '') for log in self.logs):
            failures.append("- Email filtering did not block malicious attachment")
            failures.append("- User awareness insufficient to detect phishing attempt")
        
        if any('c2' in log.get('action', '').lower() for log in self.logs):
            failures.append("- Egress filtering not blocking suspicious outbound connections")
            failures.append("- No C2 beacon detection capabilities")
        
        return '\n'.join(failures) if failures else "- Multiple defensive layers compromised"
    
    def _identify_vulnerabilities(self) -> str:
        """Identify specific vulnerabilities"""
        vulns = []
        
        for log in self.logs:
            action = log.get('action', '').lower()
            if 'password' in action and 'failed' in action:
                vulns.append("- Weak authentication credentials (CVE-N/A - Configuration Issue)")
            if 'registry' in log.get('log_type', ''):
                vulns.append("- Insufficient endpoint protection allowing persistence mechanisms")
            if 'lsass' in str(log).lower():
                vulns.append("- Credential theft via LSASS memory dumping (T1003.001)")
        
        return '\n'.join(set(vulns)) if vulns else "- Configuration weaknesses rather than specific CVEs"
    
    def _map_mitre_attack(self) -> str:
        """Map attack to MITRE ATT&CK framework"""
        techniques = []
        
        for log in self.logs:
            action = log.get('action', '').lower()
            
            if 'failed login' in action or 'brute force' in action:
                techniques.append("- T1110: Brute Force (Credential Access)")
            if 'phishing' in action or 'email' in log.get('log_type', ''):
                techniques.append("- T1566: Phishing (Initial Access)")
            if 'persistence' in action or 'registry' in log.get('log_type', ''):
                techniques.append("- T1547: Boot or Logon Autostart Execution (Persistence)")
            if 'c2' in action or 'beacon' in action:
                techniques.append("- T1071: Application Layer Protocol (Command & Control)")
            if 'lsass' in str(log).lower():
                techniques.append("- T1003: OS Credential Dumping (Credential Access)")
            if 'transfer' in action or 'exfiltration' in action:
                techniques.append("- T1041: Exfiltration Over C2 Channel")
        
        return '\n'.join(set(techniques)) if techniques else "- Multiple TTPs observed (see timeline for details)"
    
    def generate_remediation_plan(self) -> str:
        """Generate comprehensive remediation recommendations"""
        remediation = f"""
RECOMMENDED REMEDIATION
{'=' * 80}

IMMEDIATE ACTIONS (0-24 Hours):
{'=' * 40}
Priority: CRITICAL - Execute immediately

1. CONTAINMENT:
   □ Isolate all affected systems from the network
   □ Block attacker IP addresses at perimeter firewall
   □ Disable compromised user accounts
   □ Terminate malicious processes identified in timeline
   
2. ERADICATION:
   □ Remove malware files and persistence mechanisms
   □ Reset all credentials on affected systems
   □ Apply latest security patches
   □ Verify system integrity using known-good backups
   
3. EVIDENCE PRESERVATION:
   □ Create forensic images of affected systems
   □ Preserve all logs for legal/compliance requirements
   □ Document all actions taken during incident response

SHORT-TERM ACTIONS (1-7 Days):
{'=' * 40}
Priority: HIGH - Complete within one week

1. SECURITY ENHANCEMENTS:
   □ Deploy endpoint detection and response (EDR) solution
   □ Implement network segmentation
   □ Enable enhanced logging on all critical systems
   □ Deploy SIEM for centralized log analysis
   
2. THREAT HUNTING:
   □ Search for IOCs across entire network
   □ Review historical logs for similar patterns
   □ Check for additional compromised systems
   □ Validate integrity of backups
   
3. CREDENTIAL MANAGEMENT:
   □ Force password reset for all users
   □ Implement multi-factor authentication (MFA)
   □ Review and revoke unnecessary privileged access
   □ Implement privileged access management (PAM)

LONG-TERM ACTIONS (1-3 Months):
{'=' * 40}
Priority: MEDIUM - Strategic improvements

1. TECHNICAL CONTROLS:
   □ Deploy advanced threat protection solutions
   □ Implement application whitelisting
   □ Enable PowerShell logging and script block logging
   □ Deploy deception technology (honeypots)
   □ Implement network access control (NAC)
   
2. PROCESS IMPROVEMENTS:
   □ Develop/update incident response playbooks
   □ Establish security operations center (SOC)
   □ Implement security orchestration (SOAR)
   □ Create detection use cases for observed TTPs
   □ Establish threat intelligence program
   
3. PEOPLE & AWARENESS:
   □ Conduct security awareness training (phishing, social engineering)
   □ Perform tabletop exercises for incident response
   □ Establish security champions program
   □ Provide specialized training for IT/security teams

4. GOVERNANCE:
   □ Update security policies and procedures
   □ Conduct third-party security assessment
   □ Implement security metrics and KPIs
   □ Establish vulnerability management program
   □ Schedule regular penetration testing
"""
        return remediation
    
    def generate_ioc_section(self) -> str:
        """Generate IOC section for threat intelligence"""
        iocs = f"""
INDICATORS OF COMPROMISE (IOCs)
{'=' * 80}

The following IOCs should be:
- Blocked at network perimeter
- Added to threat intelligence feeds
- Used for retroactive threat hunting
- Shared with security community (TLP:WHITE)

"""
        
        # Extract unique IPs
        external_ips = set()
        for log in self.logs:
            source_ip = log.get('source_ip', '')
            if source_ip and not source_ip.startswith('192.168'):
                external_ips.add(source_ip)
            dest_ip = log.get('destination_ip', '')
            if dest_ip and not dest_ip.startswith('192.168'):
                external_ips.add(dest_ip)
        
        if external_ips:
            iocs += "\nIP ADDRESSES:\n"
            for ip in sorted(external_ips):
                iocs += f"  {ip} - Attacker infrastructure\n"
        
        # Extract file hashes
        file_hashes = set(log.get('file_hash') for log in self.logs if 'file_hash' in log)
        if file_hashes:
            iocs += "\nFILE HASHES (MD5):\n"
            for hash_val in file_hashes:
                iocs += f"  {hash_val} - Malicious executable\n"
        
        # Extract file paths
        file_paths = set(log.get('file_path') for log in self.logs if 'file_path' in log)
        if file_paths:
            iocs += "\nFILE PATHS:\n"
            for path in sorted(file_paths):
                iocs += f"  {path}\n"
        
        # Extract processes
        processes = set(log.get('process') for log in self.logs 
                       if 'process' in log and log.get('severity') in ['CRITICAL', 'HIGH'])
        if processes:
            iocs += "\nSUSPICIOUS PROCESSES:\n"
            for proc in sorted(processes):
                iocs += f"  {proc}\n"
        
        return iocs
    
    def generate_lessons_learned(self) -> str:
        """Generate lessons learned section"""
        lessons = f"""
LESSONS LEARNED
{'=' * 80}

KEY TAKEAWAYS:

1. DETECTION GAPS:
   - Lack of behavioral analytics delayed detection
   - Insufficient log aggregation and correlation
   - No real-time alerting for critical security events
   
2. RESPONSE DEFICIENCIES:
   - Incident response plan not adequately tested
   - Unclear escalation procedures
   - Limited forensic capabilities
   
3. PREVENTIVE MEASURES:
   - Basic security hygiene gaps (passwords, patching, MFA)
   - Inadequate network segmentation
   - Insufficient user awareness training

RECOMMENDATIONS FOR FUTURE PREVENTION:

TECHNICAL:
- Implement zero-trust architecture
- Deploy advanced threat detection (AI/ML-based)
- Enhance endpoint visibility and control
- Improve network segmentation
- Implement just-in-time access

OPERATIONAL:
- Regular security assessments and penetration testing
- Continuous security monitoring and threat hunting
- Regular incident response drills and tabletops
- Establish metrics for security operations effectiveness

STRATEGIC:
- Increase security budget allocation
- Hire additional security personnel
- Establish executive security steering committee
- Implement security metrics dashboard for leadership
"""
        return lessons
    
    def generate_complete_report(self) -> str:
        """Generate complete investigation report"""
        
        # Determine incident type from logs
        incident_type = "Security Incident"
        if any('brute force' in log.get('action', '').lower() for log in self.logs):
            incident_type = "Brute Force Attack"
        elif any('malware' in str(log).lower() or 'c2' in str(log).lower() for log in self.logs):
            incident_type = "Malware Infection"
        
        severity = "CRITICAL"  # Most incidents in simulator are critical
        
        report = f"""
{'=' * 80}
INCIDENT INVESTIGATION REPORT
{'=' * 80}

Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Incident ID: INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}
Classification: CONFIDENTIAL - FOR INTERNAL USE ONLY
Prepared By: Security Operations Center (SOC)

{'=' * 80}

"""
        report += self.generate_executive_summary(incident_type, severity)
        report += "\n\n"
        report += self.generate_timeline_section()
        report += "\n\n"
        report += self.generate_root_cause_analysis()
        report += "\n\n"
        report += self.generate_remediation_plan()
        report += "\n\n"
        report += self.generate_ioc_section()
        report += "\n\n"
        report += self.generate_lessons_learned()
        
        report += f"""

{'=' * 80}
APPENDIX: TECHNICAL ANALYSIS
{'=' * 80}

{self.analysis}

{'=' * 80}
END OF REPORT
{'=' * 80}

This report contains sensitive security information and should be handled 
according to your organization's data classification policies.

Distribution List:
- Chief Information Security Officer (CISO)
- IT Director
- Security Operations Manager
- Compliance Officer
- Legal Department (if required)
"""
        
        return report

def main():
    if len(sys.argv) < 2:
        print("Usage: python report_generator.py <log_file.json>")
        print("\nExample:")
        print("  python report_generator.py ../logs/brute_force_attack_20240129_120000.json")
        sys.exit(1)
    
    log_file = sys.argv[1]
    
    print("[*] Generating incident investigation report...")
    generator = ReportGenerator(log_file)
    generator.load_data()
    
    report = generator.generate_complete_report()
    
    # Save report
    report_file = log_file.replace('.json', '_INVESTIGATION_REPORT.txt')
    with open(report_file, 'w') as f:
        f.write(report)
    
    print(f"[+] Investigation report generated: {report_file}")
    print("\n" + "=" * 80)
    print("REPORT PREVIEW:")
    print("=" * 80)
    print(report[:2000])
    print("\n... [Report continues] ...\n")
    print(f"[+] Full report saved to: {report_file}")

if __name__ == "__main__":
    main()
