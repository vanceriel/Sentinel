#!/usr/bin/env python3
"""
Log Analyzer for Incident Investigation
Provides tools to analyze and investigate security incident logs
"""

import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime
from typing import List, Dict, Set

class LogAnalyzer:
    def __init__(self, log_file: str):
        self.log_file = log_file
        self.logs = []
        self.load_logs()
    
    def load_logs(self):
        """Load logs from JSON file"""
        try:
            with open(self.log_file, 'r') as f:
                self.logs = json.load(f)
            print(f"[+] Loaded {len(self.logs)} log entries from {self.log_file}")
        except FileNotFoundError:
            print(f"[!] Error: Log file '{self.log_file}' not found")
            sys.exit(1)
        except json.JSONDecodeError:
            print(f"[!] Error: Invalid JSON in log file")
            sys.exit(1)
    
    def analyze_ips(self) -> Dict:
        """Analyze IP addresses in logs"""
        source_ips = []
        dest_ips = []
        
        for log in self.logs:
            if 'source_ip' in log:
                source_ips.append(log['source_ip'])
            if 'destination_ip' in log:
                dest_ips.append(log['destination_ip'])
        
        return {
            "unique_source_ips": len(set(source_ips)),
            "unique_dest_ips": len(set(dest_ips)),
            "top_source_ips": Counter(source_ips).most_common(5),
            "top_dest_ips": Counter(dest_ips).most_common(5)
        }
    
    def identify_attack_pattern(self) -> Dict:
        """Identify attack patterns from logs"""
        patterns = {
            "failed_logins": 0,
            "successful_logins": 0,
            "suspicious_commands": [],
            "persistence_indicators": [],
            "c2_communications": [],
            "data_transfers": []
        }
        
        for log in self.logs:
            action = log.get('action', '').lower()
            
            if 'failed login' in action:
                patterns["failed_logins"] += 1
            
            if 'successful login' in action:
                patterns["successful_logins"] += 1
            
            if 'command' in log.get('log_type', ''):
                patterns["suspicious_commands"].append({
                    "timestamp": log.get('timestamp'),
                    "command": log.get('command'),
                    "description": log.get('action')
                })
            
            if 'registry' in log.get('log_type', '') or 'persistence' in action:
                patterns["persistence_indicators"].append({
                    "timestamp": log.get('timestamp'),
                    "details": log.get('message', log.get('action'))
                })
            
            if 'c2' in action or 'beacon' in action:
                patterns["c2_communications"].append({
                    "timestamp": log.get('timestamp'),
                    "source": log.get('source_ip'),
                    "destination": log.get('destination_ip')
                })
            
            if 'transfer' in action or 'exfiltration' in action:
                patterns["data_transfers"].append({
                    "timestamp": log.get('timestamp'),
                    "bytes": log.get('bytes_transferred', 'Unknown'),
                    "details": log.get('message', '')
                })
        
        return patterns
    
    def create_timeline(self) -> List[Dict]:
        """Create chronological timeline of events"""
        timeline = sorted(self.logs, key=lambda x: x.get('timestamp', ''))
        return timeline
    
    def analyze_severity(self) -> Dict:
        """Analyze log severity distribution"""
        severity_counts = Counter(log.get('severity', 'UNKNOWN') for log in self.logs)
        return dict(severity_counts)
    
    def find_iocs(self) -> Dict:
        """Extract Indicators of Compromise (IOCs)"""
        iocs = {
            "ip_addresses": set(),
            "file_hashes": set(),
            "file_paths": set(),
            "domains": set(),
            "suspicious_processes": set()
        }
        
        for log in self.logs:
            # IP addresses
            if 'source_ip' in log and not log['source_ip'].startswith('192.168'):
                iocs["ip_addresses"].add(log['source_ip'])
            if 'destination_ip' in log and not log['destination_ip'].startswith('192.168'):
                iocs["ip_addresses"].add(log['destination_ip'])
            
            # File hashes
            if 'file_hash' in log:
                iocs["file_hashes"].add(log['file_hash'])
            
            # File paths
            if 'file_path' in log:
                iocs["file_paths"].add(log['file_path'])
            
            # Processes
            if 'process' in log and log.get('severity') in ['CRITICAL', 'HIGH']:
                iocs["suspicious_processes"].add(log['process'])
        
        # Convert sets to lists for JSON serialization
        return {k: list(v) for k, v in iocs.items()}
    
    def generate_report(self) -> str:
        """Generate comprehensive analysis report"""
        report = []
        report.append("=" * 80)
        report.append("INCIDENT ANALYSIS REPORT")
        report.append("=" * 80)
        report.append(f"\nAnalysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Log File: {self.log_file}")
        report.append(f"Total Events: {len(self.logs)}\n")
        
        # IP Analysis
        report.append("\n" + "=" * 80)
        report.append("IP ADDRESS ANALYSIS")
        report.append("=" * 80)
        ip_analysis = self.analyze_ips()
        report.append(f"\nUnique Source IPs: {ip_analysis['unique_source_ips']}")
        report.append(f"Unique Destination IPs: {ip_analysis['unique_dest_ips']}")
        report.append("\nTop Source IPs:")
        for ip, count in ip_analysis['top_source_ips']:
            report.append(f"  {ip}: {count} events")
        report.append("\nTop Destination IPs:")
        for ip, count in ip_analysis['top_dest_ips']:
            report.append(f"  {ip}: {count} events")
        
        # Severity Analysis
        report.append("\n" + "=" * 80)
        report.append("SEVERITY DISTRIBUTION")
        report.append("=" * 80)
        severity = self.analyze_severity()
        for level, count in sorted(severity.items(), key=lambda x: x[1], reverse=True):
            report.append(f"{level}: {count} events")
        
        # Attack Pattern Analysis
        report.append("\n" + "=" * 80)
        report.append("ATTACK PATTERN ANALYSIS")
        report.append("=" * 80)
        patterns = self.identify_attack_pattern()
        
        if patterns['failed_logins'] > 0:
            report.append(f"\n[!] Failed Login Attempts: {patterns['failed_logins']}")
        if patterns['successful_logins'] > 0:
            report.append(f"[!] Successful Logins: {patterns['successful_logins']}")
        
        if patterns['suspicious_commands']:
            report.append("\n[!] Suspicious Commands Executed:")
            for cmd in patterns['suspicious_commands']:
                report.append(f"  - {cmd['timestamp']}: {cmd['command']} ({cmd['description']})")
        
        if patterns['persistence_indicators']:
            report.append("\n[!] Persistence Mechanisms Detected:")
            for ind in patterns['persistence_indicators']:
                report.append(f"  - {ind['timestamp']}: {ind['details']}")
        
        if patterns['c2_communications']:
            report.append("\n[!] Command & Control Communications:")
            for c2 in patterns['c2_communications']:
                report.append(f"  - {c2['timestamp']}: {c2['source']} -> {c2['destination']}")
        
        if patterns['data_transfers']:
            report.append("\n[!] Data Exfiltration Detected:")
            for transfer in patterns['data_transfers']:
                report.append(f"  - {transfer['timestamp']}: {transfer['bytes']} bytes - {transfer['details']}")
        
        # IOCs
        report.append("\n" + "=" * 80)
        report.append("INDICATORS OF COMPROMISE (IOCs)")
        report.append("=" * 80)
        iocs = self.find_iocs()
        
        if iocs['ip_addresses']:
            report.append("\nSuspicious IP Addresses:")
            for ip in iocs['ip_addresses']:
                report.append(f"  - {ip}")
        
        if iocs['file_hashes']:
            report.append("\nMalicious File Hashes:")
            for hash_val in iocs['file_hashes']:
                report.append(f"  - {hash_val}")
        
        if iocs['file_paths']:
            report.append("\nSuspicious File Paths:")
            for path in iocs['file_paths']:
                report.append(f"  - {path}")
        
        if iocs['suspicious_processes']:
            report.append("\nSuspicious Processes:")
            for proc in iocs['suspicious_processes']:
                report.append(f"  - {proc}")
        
        return "\n".join(report)
    
    def interactive_query(self):
        """Interactive query mode for log investigation"""
        while True:
            print("\n" + "=" * 80)
            print("INTERACTIVE LOG QUERY")
            print("=" * 80)
            print("\n1. Search by IP address")
            print("2. Search by severity level")
            print("3. Search by time range")
            print("4. Search by keyword")
            print("5. Show all critical events")
            print("6. Exit")
            
            choice = input("\nEnter choice (1-6): ").strip()
            
            if choice == "1":
                ip = input("Enter IP address: ").strip()
                results = [log for log in self.logs 
                          if log.get('source_ip') == ip or log.get('destination_ip') == ip]
                self.display_results(results)
            
            elif choice == "2":
                severity = input("Enter severity level (INFO/WARNING/HIGH/CRITICAL): ").strip().upper()
                results = [log for log in self.logs if log.get('severity') == severity]
                self.display_results(results)
            
            elif choice == "3":
                print("Enter time range (format: YYYY-MM-DDTHH:MM:SS)")
                start = input("Start time: ").strip()
                end = input("End time: ").strip()
                results = [log for log in self.logs 
                          if start <= log.get('timestamp', '') <= end]
                self.display_results(results)
            
            elif choice == "4":
                keyword = input("Enter keyword to search: ").strip().lower()
                results = [log for log in self.logs 
                          if keyword in str(log).lower()]
                self.display_results(results)
            
            elif choice == "5":
                results = [log for log in self.logs if log.get('severity') == 'CRITICAL']
                self.display_results(results)
            
            elif choice == "6":
                print("\nExiting interactive mode...")
                break
            
            else:
                print("[!] Invalid choice. Please try again.")
    
    def display_results(self, results: List[Dict]):
        """Display search results"""
        if not results:
            print("\n[!] No results found.")
            return
        
        print(f"\n[+] Found {len(results)} matching events:\n")
        for idx, log in enumerate(results, 1):
            print(f"[{idx}] {log.get('timestamp', 'N/A')}")
            print(f"    Action: {log.get('action', 'N/A')}")
            print(f"    Severity: {log.get('severity', 'N/A')}")
            if 'source_ip' in log:
                print(f"    Source: {log.get('source_ip')}")
            if 'destination_ip' in log:
                print(f"    Destination: {log.get('destination_ip')}")
            if 'message' in log:
                print(f"    Details: {log.get('message')}")
            print()

def main():
    if len(sys.argv) < 2:
        print("Usage: python log_analyzer.py <log_file.json> [--interactive]")
        print("\nExample:")
        print("  python log_analyzer.py ../logs/brute_force_attack_20240129_120000.json")
        print("  python log_analyzer.py ../logs/malware_infection_20240129_120000.json --interactive")
        sys.exit(1)
    
    log_file = sys.argv[1]
    interactive = "--interactive" in sys.argv
    
    analyzer = LogAnalyzer(log_file)
    
    if interactive:
        analyzer.interactive_query()
    else:
        # Generate and display report
        report = analyzer.generate_report()
        print(report)
        
        # Save report
        report_file = log_file.replace('.json', '_analysis.txt')
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"\n[+] Analysis report saved to: {report_file}")

if __name__ == "__main__":
    main()
