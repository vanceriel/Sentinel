import subprocess
import sys
import os
import glob

print("=" * 50)
print("SENTINEL: Incident Investigation Simulator")
print("=" * 50)

# Step 1: Run simulator (requires user input — type 1 or 2 or 3)
print("\nStep 1: Generating incident logs...")
subprocess.run([sys.executable, "incident_simulator.py"])

# Step 2: Find all newly generated .json log files
json_files = glob.glob("logs/*.json")
if not json_files:
    print("\n[!] No log file found. Make sure incident_simulator.py ran successfully.")
    sys.exit(1)

# Sort by most recently modified
json_files = sorted(json_files, key=os.path.getmtime)

print(f"\n[+] Found {len(json_files)} log file(s):")
for f in json_files:
    print(f"    {f}")

# Step 3: Run analyzer and report generator on each file
for log_file in json_files:
    print(f"\nStep 2: Analyzing {log_file}...")
    subprocess.run([sys.executable, "log_analyzer.py", log_file])

    print(f"\nStep 3: Generating report for {log_file}...")
    subprocess.run([sys.executable, "report_generator.py", log_file])

print("\n[✓] Done. Check the logs folder for output files.")
