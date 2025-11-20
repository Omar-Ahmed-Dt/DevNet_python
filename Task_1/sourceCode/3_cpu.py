import os
import re
from modules.mod import get_log_files

# logs formate
LINE_REGEX = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) "
    r"(?P<device>\S+) "
    r"(?P<level>\S+) "
    r"(?P<event>.+)"
)


parent_dir_path, files = get_log_files()

def detect_cpu_flaps(files):
    events = {}   # device -> list of (minutes)

    for filename in files:
        filepath = os.path.join(parent_dir_path, filename)

        with open(filepath, "r") as file:
            for line in file:
                line_formate = LINE_REGEX.match(line.strip())
                if not line_formate: 
                    continue

                parts = line.split()

                # need at least date time device cpu%
                if len(parts) < 4:
                    continue

                last = parts[-1]     # example "85%" at end

                # must end with % and be numeric
                if not last.endswith("%"):
                    continue

                cpu_str = last[:-1]   # remove %
                if not cpu_str.isdigit():
                    continue

                cpu_value = int(cpu_str)

                # Only consider CPU > 80
                if cpu_value <= 80:
                    continue

                # extract time
                time_str = parts[1]   # HH:MM:SS
                device   = parts[2]

                time_parts = time_str.split(":")
                hour = int(time_parts[0])
                minute = int(time_parts[1])

                total_minutes = hour * 60 + minute

                if device not in events:
                    events[device] = []

                events[device].append(total_minutes)

    # Detect CPU (>2 in 60 minutes)
    print("\n## CPU >80% more than 2 times in 1 hour: \n")

    for device in events:
        times = events[device]
        times.sort()

        if len(times) < 3:
            continue   # cannot be >2

        for i in range(len(times)):
            count = 1
            for j in range(i + 1, len(times)):
                if times[j] - times[i] <= 60: 
                    count += 1
                else:
                    break

            if count > 2:
                print(f"{device}: {count} high-CPU events within 1 hour")
                break


detect_cpu_flaps(files)