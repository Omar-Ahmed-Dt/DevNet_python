import os
import sys
import re 
from modules.mod import get_log_files

parent_dir_path, files = get_log_files()

# logs formate
LINE_REGEX = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) "
    r"(?P<device>\S+) "
    r"(?P<level>\S+) "
    r"(?P<event>.+)"
)

# grep info based on required_info func
def print_info(files, parent_dir_path, required_info):
    for filename in files:
        print("\n## File Name: ", filename, '\n')
        filepath = os.path.join(parent_dir_path, filename)

        with open(filepath, "r") as f:
            for line in f:
                # skip empty line
                # if not line.strip():
                #     continue
                line_formate = LINE_REGEX.match(line.strip())
                if not line_formate: 
                    continue

                parts = line.strip().split()
                required_info(parts)

# 1. timeStamp
def timestamp(parts):
    print(parts[0], parts[1])

# 2. deviceName
def device(parts):
    print(parts[2])

# 3. eventType && 4. keyDetails
def event_type(parts):
    print(parts[4], parts[5], parts[-1])

# Ask what they want
print("Choose what you want to extract: \n"
"1) Time Stamps \n"
"2) Device Names \n"
"3) Event Type + Key Details \n")

choice = input("Enter choice (1-4): ")

if choice == "1":
    print("\n## Time Stamps:")
    print_info(files, parent_dir_path, timestamp)

elif choice == "2":
    print("\n## Device Names:")
    print_info(files, parent_dir_path, device)

elif choice == "3":
    print("\n## Event Type + Key Details:")
    print_info(files, parent_dir_path, event_type)

else:
    print("Invalid choice!")