#!/usr/bin/env python3
"""
Incident Investigation Simulator
Simulates cybersecurity incidents and generates realistic logs for investigation practice
"""

import json
import random
import datetime
import hashlib
import sys
import os
from typing import List, Dict, Tuple

class IncidentSimulator:
    def __init__(self, output_dir: str = "logs"): #saves output in logs/ folder
        self.output_dir = output_dir
        self.incidents = []
        
    def generate_timestamp(self, base_time: datetime.datetime, offset_minutes: int) -> str:
        """Generate ISO format timestamp with offset"""
        return (base_time + datetime.timedelta(minutes=offset_minutes)).isoformat() + "Z"
    
    def generate_ip(self, internal: bool = False) -> str:
        """Generate realistic IP addresses"""
        if internal:
            return f"192.168.{random.randint(1, 50)}.{random.randint(1, 254)}"
        else:
            # Simulate external attacker IPs
            return f"{random.randint(1, 223)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
    
    def simulate_brute_force_attack(self) -> Tuple[List[Dict], Dict]:
        """
        Simulate a brute force SSH attack scenario
        Returns: (log_entries, incident_metadata)
        """
        print("\n[*] Simulating Brute Force Attack...")
        
        base_time = datetime.datetime.now() - datetime.timedelta(hours=2)
        attacker_ip = self.generate_ip(internal=False)
        target_ip = self.generate_ip(internal=True)
        target_user = "admin"
        
        logs = []
        incident_metadata = {
            "incident_type": "Brute Force Attack",
            "attacker_ip": attacker_ip,
            "target_ip": target_ip,
            "target_user": target_user,
            "attack_start": base_time.isoformat(),
            "successful_login": None
        }
        
        # Phase 1: Initial reconnaissance (port scan)
        for i in range(3):
            logs.append({
                "timestamp": self.generate_timestamp(base_time, i),
                "source_ip": attacker_ip,
                "destination_ip": target_ip,
                "destination_port": random.choice([22, 80, 443, 3389]),
                "protocol": "TCP",
                "action": "SYN",
                "log_type": "firewall",
                "severity": "INFO"
            })
        
        # Phase 2: Failed login attempts (brute force)
        failed_attempts = random.randint(45, 75)
        for i in range(failed_attempts):
            logs.append({
                "timestamp": self.generate_timestamp(base_time, 5 + i),
                "source_ip": attacker_ip,
                "destination_ip": target_ip,
                "destination_port": 22,
                "user": target_user,
                "action": "Failed login",
                "password_attempt": f"pass{random.randint(1000, 9999)}",
                "log_type": "auth",
                "severity": "WARNING",
                "message": f"Failed password for {target_user} from {attacker_ip} port 52891 ssh2"
            })
        
        # Phase 3: Successful breach
        success_time = 5 + failed_attempts + 5
        logs.append({
            "timestamp": self.generate_timestamp(base_time, success_time),
            "source_ip": attacker_ip,
            "destination_ip": target_ip,
            "destination_port": 22,
            "user": target_user,
            "action": "Successful login",
            "log_type": "auth",
            "severity": "CRITICAL",
            "message": f"Accepted password for {target_user} from {attacker_ip} port 52891 ssh2"
        })
        
        incident_metadata["successful_login"] = self.generate_timestamp(base_time, success_time)
        
        # Phase 4: Post-compromise activity
        post_activities = [
            ("sudo su", "Privilege escalation attempt"),
            ("cat /etc/passwd", "Password file enumeration"),
            ("find / -name *.conf", "Configuration file discovery"),
            ("netstat -an", "Network connection enumeration"),
            ("ps aux", "Process enumeration")
        ]
        
        for idx, (command, description) in enumerate(post_activities):
            logs.append({
                "timestamp": self.generate_timestamp(base_time, success_time + 2 + idx),
                "source_ip": attacker_ip,
                "destination_ip": target_ip,
                "user": target_user,
                "command": command,
                "action": description,
                "log_type": "command",
                "severity": "CRITICAL"
            })
        
        # Phase 5: Data exfiltration
        logs.append({
            "timestamp": self.generate_timestamp(base_time, success_time + 15),
            "source_ip": target_ip,
            "destination_ip": attacker_ip,
            "destination_port": 443,
            "protocol": "HTTPS",
            "bytes_transferred": 5242880,  # 5MB
            "action": "Large outbound transfer",
            "log_type": "network",
            "severity": "CRITICAL",
            "message": "Unusual outbound data transfer detected"
        })
        
        return logs, incident_metadata
    
    def simulate_malware_infection(self) -> Tuple[List[Dict], Dict]:
        """
        Simulate a malware infection scenario
        Returns: (log_entries, incident_metadata)
        """
        print("\n[*] Simulating Malware Infection...")
        
        base_time = datetime.datetime.now() - datetime.timedelta(hours=4)
        infected_host = self.generate_ip(internal=True)
        c2_server = self.generate_ip(internal=False)
        malware_hash = hashlib.md5(b"malware_sample_" + str(random.randint(1000, 9999)).encode()).hexdigest()
        
        logs = []
        incident_metadata = {
            "incident_type": "Malware Infection",
            "infected_host": infected_host,
            "c2_server": c2_server,
            "malware_hash": malware_hash,
            "infection_time": base_time.isoformat(),
            "malware_family": "TrickBot"
        }
        
        # Phase 1: Initial infection vector (phishing email)
        logs.append({
            "timestamp": self.generate_timestamp(base_time, 0),
            "source_ip": "smtp.external.com",
            "destination_ip": infected_host,
            "user": "john.doe@company.com",
            "subject": "URGENT: Invoice Payment Required",
            "attachment": "invoice_2024.pdf.exe",
            "action": "Email received",
            "log_type": "email",
            "severity": "WARNING",
            "message": "Suspicious attachment detected in email"
        })
        
        # Phase 2: File execution
        logs.append({
            "timestamp": self.generate_timestamp(base_time, 5),
            "host": infected_host,
            "process": "invoice_2024.pdf.exe",
            "parent_process": "outlook.exe",
            "file_path": "C:\\Users\\john.doe\\Downloads\\invoice_2024.pdf.exe",
            "file_hash": malware_hash,
            "action": "Process created",
            "log_type": "endpoint",
            "severity": "CRITICAL",
            "message": "Suspicious executable launched from email attachment"
        })
        
        # Phase 3: Persistence mechanism
        logs.append({
            "timestamp": self.generate_timestamp(base_time, 6),
            "host": infected_host,
            "registry_key": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "registry_value": "WindowsUpdate",
            "registry_data": "C:\\Windows\\Temp\\svchost.exe",
            "action": "Registry modification",
            "log_type": "endpoint",
            "severity": "CRITICAL",
            "message": "Suspicious registry key created for persistence"
        })
        
        # Phase 4: Command and Control (C2) communication
        for i in range(8):
            logs.append({
                "timestamp": self.generate_timestamp(base_time, 10 + i * 5),
                "source_ip": infected_host,
                "destination_ip": c2_server,
                "destination_port": 443,
                "protocol": "HTTPS",
                "bytes_sent": random.randint(512, 2048),
                "bytes_received": random.randint(256, 1024),
                "action": "Suspicious C2 beacon",
                "log_type": "network",
                "severity": "CRITICAL",
                "message": f"Regular beaconing to suspicious IP {c2_server}"
            })
        
        # Phase 5: Lateral movement attempt
        internal_targets = [self.generate_ip(internal=True) for _ in range(3)]
        for idx, target in enumerate(internal_targets):
            logs.append({
                "timestamp": self.generate_timestamp(base_time, 50 + idx * 2),
                "source_ip": infected_host,
                "destination_ip": target,
                "destination_port": 445,  # SMB
                "protocol": "SMB",
                "action": "Connection attempt",
                "log_type": "network",
                "severity": "HIGH",
                "message": f"Suspicious SMB connection from {infected_host} to {target}"
            })
        
        # Phase 6: Credential harvesting
        logs.append({
            "timestamp": self.generate_timestamp(base_time, 60),
            "host": infected_host,
            "process": "svchost.exe",
            "target_process": "lsass.exe",
            "action": "Process memory read",
            "log_type": "endpoint",
            "severity": "CRITICAL",
            "message": "Suspicious process accessing LSASS memory (credential theft attempt)"
        })
        
        # Phase 7: Data staging
        logs.append({
            "timestamp": self.generate_timestamp(base_time, 70),
            "host": infected_host,
            "file_path": "C:\\Windows\\Temp\\data.zip",
            "file_size": 52428800,  # 50MB
            "action": "Large file created",
            "log_type": "endpoint",
            "severity": "HIGH",
            "message": "Large archive created in temporary directory"
        })
        
        # Phase 8: Exfiltration
        logs.append({
            "timestamp": self.generate_timestamp(base_time, 75),
            "source_ip": infected_host,
            "destination_ip": c2_server,
            "destination_port": 443,
            "protocol": "HTTPS",
            "bytes_transferred": 52428800,
            "action": "Large data transfer",
            "log_type": "network",
            "severity": "CRITICAL",
            "message": "Large outbound data transfer to suspicious IP"
        })
        
        return logs, incident_metadata
    
    def save_logs(self, logs: List[Dict], incident_type: str):
        """Save logs to JSON file"""
        os.makedirs(self.output_dir, exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.output_dir}/{incident_type.lower().replace(' ', '_')}_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(logs, f, indent=2)
        
        print(f"[+] Logs saved to: {filename}")
        return filename
    
    def generate_timeline(self, logs: List[Dict], metadata: Dict) -> str:
        """Generate human-readable timeline"""
        timeline = []
        timeline.append("=" * 80)
        timeline.append("INCIDENT TIMELINE")
        timeline.append("=" * 80)
        timeline.append(f"\nIncident Type: {metadata['incident_type']}")
        timeline.append("\nChronological Events:\n")
        
        for idx, log in enumerate(logs, 1):
            timeline.append(f"[{idx}] {log['timestamp']}")
            timeline.append(f"    Action: {log['action']}")
            timeline.append(f"    Severity: {log['severity']}")
            if 'source_ip' in log:
                timeline.append(f"    Source: {log['source_ip']}")
            if 'destination_ip' in log:
                timeline.append(f"    Destination: {log['destination_ip']}")
            if 'message' in log:
                timeline.append(f"    Details: {log['message']}")
            timeline.append("")
        
        return "\n".join(timeline)

def main():
    print("=" * 80)
    print("SENTINEL")
    print("=" * 80)
    
    simulator = IncidentSimulator()
    
    '''
    print("\nSelect incident type to simulate:")
    print("1. Brute Force Attack")
    print("2. Malware Infection")
    print("3. Both")
    
    choice = input("\nEnter choice (1-3): ").strip()
    '''

if os.environ.get("RUN_PY"):
    # Called from run.py — show all 3 options
    print("\nSelect incident type to simulate:")
    print("1. Brute Force Attack")
    print("2. Malware Infection")
    print("3. Both")
    try:
        choice = input("\nEnter choice (1-3): ").strip()
    except KeyboardInterrupt:
        print("\n[!] Cancelled.")
        sys.exit(0)
    if choice not in ["1", "2", "3"]:
        print("[!] Invalid choice. Enter 1, 2, or 3.")
        sys.exit(1)
else:
    # Called directly — show options 1 and 2 only
    print("\nSelect incident type to simulate:")
    print("1. Brute Force Attack")
    print("2. Malware Infection")
    choice = input("\nEnter choice (1-2): ").strip()
    if choice not in ["1", "2"]:
        print("[!] Invalid choice. Enter 1 or 2. For both scenarios, use run.py.")
        sys.exit(1)
    
    incidents = []
    
    if choice in ["1", "3"]:
        logs, metadata = simulator.simulate_brute_force_attack()
        filename = simulator.save_logs(logs, metadata['incident_type'])
        timeline = simulator.generate_timeline(logs, metadata)
        incidents.append((metadata['incident_type'], filename, timeline, metadata))
    
    if choice in ["2", "3"]:
        logs, metadata = simulator.simulate_malware_infection()
        filename = simulator.save_logs(logs, metadata['incident_type'])
        timeline = simulator.generate_timeline(logs, metadata)
        incidents.append((metadata['incident_type'], filename, timeline, metadata))
    
    # Save timelines
    for incident_type, log_file, timeline, metadata in incidents:
        timeline_file = log_file.replace('.json', '_timeline.txt')
        with open(timeline_file, 'w') as f:
            f.write(timeline)
        print(f"[+] Timeline saved to: {timeline_file}")
    
    print("\n[✓] Simulation complete!")
    print("\nNext steps:")
    print("1. Analyze the generated logs in the 'logs' directory")
    print("2. Use log_analyzer.py to investigate the incident")
    print("3. Document your findings using the investigation template")

if __name__ == "__main__":
    main()
