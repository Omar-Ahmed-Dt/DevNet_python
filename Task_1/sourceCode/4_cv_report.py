import os
import re
import csv
from collections import defaultdict
from modules.mod import get_log_files  

LINE_REGEX = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) "
    r"(?P<device>\S+) "
    r"(?P<level>\S+) "
    r"(?P<event>.+)"
)

SEVERITY_ORDER = {"INFO": 1, "WARNING": 2, "ERROR": 3}

def map_risk(level: str) -> str:
    if level == "ERROR":
        return "High"
    if level == "WARNING":
        return "Medium"
    return "Low"

def main():
    parent_dir_path, files = get_log_files()

    # Build full file paths using parent_dir_path
    file_paths = []
    for f in files:
        file_paths.append(os.path.join(parent_dir_path, f))

    # Parse logs
    data = defaultdict(lambda: {
        "count": 0,
        "last_seen": "",
        "max_level": "INFO"
    })

    for file_path in file_paths:
        with open(file_path, "r") as f:
            for line in f:
                m = LINE_REGEX.match(line.strip())
                if not m:
                    continue

                ts = m.group("timestamp")
                device = m.group("device")
                level = m.group("level")
                event = m.group("event")

                key = (device, event)
                entry = data[key]

                # Count occurrences
                entry["count"] += 1

                # Update last seen timestamp
                if entry["last_seen"] == "" or ts > entry["last_seen"]:
                    entry["last_seen"] = ts

                # Track highest severity
                if SEVERITY_ORDER.get(level, 0) > SEVERITY_ORDER.get(entry["max_level"], 0):
                    entry["max_level"] = level

    # Write CSV output
    output_path = os.path.join(parent_dir_path, "report.csv")

    with open(output_path, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Device", "Event", "Count", "Last_Seen", "Risk_Level"])

        for (device, event), entry in data.items():
            risk = map_risk(entry["max_level"])
            writer.writerow([
                device,
                event,
                entry["count"],
                entry["last_seen"],
                risk
            ])

    print(f"## CSV report created: {output_path}")

main()