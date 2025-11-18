# sys.argv: catch the script name and the next parameter that contains the log files (pwd)
# python.py ../
import os
import sys

def get_log_files():
    parent_dir_path = sys.argv[1]
    files = []
    for file in os.listdir(parent_dir_path):
        if file.endswith(".log"):
            files.append(file)

    return parent_dir_path, files
