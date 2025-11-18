import os
from modules.mod import get_log_files

parent_dir_path, files = get_log_files()

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
                # check lines that didn't cotain "BGP"
                if "BGP" not in line or "down" not in line:
                    continue

                parts = line.split()
                date = parts[0]
                time = parts[1]
                device = parts[2]

                mins = to_minutes(time)

                events.setdefault(device, []).append((date, mins))

    # detect Flapping (>3 in 10 minutes)
    print("\n## BGP flap dtection (>3 in 10 minutes)\n")

    for device, timestamps in events.items():

        # Sort by date + time (simple tuple sort)
        timestamps.sort()

        times = []
        for t in timestamps:
            # t looks like ("2025-10-17", 450)
            minute_value = t[1]
            times.append(minute_value)

        if len(times) < 4:
            continue

        for i in range(len(times)):
            window = 1
            for j in range(i + 1, len(times)):
                if times[j] - times[i] <= 10:
                    window += 1
                else:
                    break

            if window > 3:
                print(f"{device}: {window} BGP Down flaps within 10 minutes")
                break

detect_bgp_flaps(files)