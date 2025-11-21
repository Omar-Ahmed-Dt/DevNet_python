import os
import re
from modules.mod import get_log_files

parent_dir_path, files = get_log_files()

# Regex to match ONLY BGP down lines
bgp_down_regex = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
    r"(?P<device>\S+)\s+INFO\s+BGP neighbor\s+"
    r"(?P<neighbor>\d+\.\d+\.\d+\.\d+)\s+went down"
)

def to_minutes(time_str):
    # "15:22:33" => 15*60 + 22 = 922 minutes
    parts = time_str.split(":")
    hour = int(parts[0])
    minute = int(parts[1])
    return hour * 60 + minute


def detect_bgp_flaps(files):
    events = {} 

    for filename in files:
        filepath = os.path.join(parent_dir_path, filename)

        with open(filepath, "r") as file:
            for line in file:
                line = line.strip()

                # match only BGP down lines
                bgp_line_formate = bgp_down_regex.match(line)
                if not bgp_line_formate:
                    continue

                # print("[BGP DOWN]", line.strip())
                parts   = line.split()
                date    = parts[0]
                time    = parts[1]
                device  = parts[2]

                mins = to_minutes(time)

                events.setdefault(device, []).append((date, mins))
                # returns pairs (device, list_of_tuples [(date,mins)] ): 
                # print(events.items())
                """
                Example: 
                dict_items([('R4', [('2025-10-19', 412)])])
                dict_items([('R4', [('2025-10-19', 412)]), ('R1', [('2025-10-19', 420)])])
                dict_items([('R4', [('2025-10-19', 412)]), ('R1', [('2025-10-19', 420)]), ('R3', [('2025-10-19', 437)])])
                """

    # detect Flapping (>3 in 10 minutes)
    print("\n## BGP flap dtection (>3 in 10 minutes)\n")

    for device, timestamps in events.items():

        # Sort by date + time (simple tuple sort)
        timestamps.sort()

        times = []
        for t in timestamps:
            # t looks like ("2025-10-17", 450)
            minute_value = t[1] # t[1] = 450
            times.append(minute_value)

        # skip flap times < 3
        if len(times) < 3:
            continue

        for i in range(len(times)):
            window = 1
            for j in range(i + 1, len(times)):
                if times[j] - times[i] <= 10:
                    window += 1
                else:
                    break

            if window >= 3:
                print(f"{device}: {window} BGP Down flaps within 10 minutes")
                break

detect_bgp_flaps(files)
