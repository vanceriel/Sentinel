import subprocess
import sys
import os
import glob

print("=" * 50)
print("SENTINEL: Incident Investigation Simulator")
print("=" * 50)

# Step 1: Run simulator (requires user input — type 1 or 2)
print("\nStep 1: Generating incident logs...")
subprocess.run([sys.executable, "incident_simulator.py"])

# Step 2: Find the most recently generated .json log file
json_files = glob.glob("*.json")
if not json_files:
    print("\n[!] No log file found. Make sure incident_simulator.py ran successfully.")
    sys.exit(1)

latest = max(json_files, key=os.path.getmtime)
print(f"\n[+] Using log file: {latest}")

# Step 3: Run analyzer
print("\nStep 2: Analyzing logs...")
subprocess.run([sys.executable, "log_analyzer.py", latest])

# Step 4: Run report generator
print("\nStep 3: Generating report...")
subprocess.run([sys.executable, "report_generator.py", latest])

print("\n[✓] Done. Check the Sentinel folder for output files.")
