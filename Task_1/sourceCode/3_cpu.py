import os
import re
from modules.mod import get_log_files

# CPU exceeded
cpu_exceeded_regex = re.compile(
    r"^\s*(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
    r"(?P<device>\S+)\s+INFO\s+CPU utilization exceeded\s+"
    r"(?P<value>\d+)%\s*$",
    re.IGNORECASE
)


parent_dir_path, files = get_log_files()

def detect_cpu_flaps(files):
    events = {}

    for filename in files:
        filepath = os.path.join(parent_dir_path, filename)

        with open(filepath, "r") as file:
            for line in file:
                cpu_exceeded_line_formate = cpu_exceeded_regex.match(line.strip())
                if not cpu_exceeded_line_formate: 
                    continue

                parts = line.split()

                last = parts[-1]     # example "85%" at end

                cpu_str = last[:-1]   # remove %
                if not cpu_str.isdigit():
                    continue

                cpu_value = int(cpu_str)

                # Only consider CPU > 80
                if cpu_value <= 80:
                    continue

                time_str = parts[1]
                device   = parts[2]

                time_parts = time_str.split(":")
                hour = int(time_parts[0])
                minute = int(time_parts[1])

                total_minutes = hour * 60 + minute

                if device not in events:
                    events[device] = []

                events[device].append(total_minutes)
                # print(events.items())
                """
                dict_items([('R2', [415])])
                dict_items([('R2', [415]), ('R4', [433])])
                dict_items([('R2', [415]), ('R4', [433, 562])])
                dict_items([('R2', [415]), ('R4', [433, 562]), ('R1', [573])])
                """

    # Detect CPU (>2 in 60 minutes)
    print("\n## CPU >80% more than 2 times in 1 hour: \n")

    for device in events:
        times = events[device]
        times.sort()

        if len(times) < 2:
            continue

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
