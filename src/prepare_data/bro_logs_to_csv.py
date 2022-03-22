'''
This is a script for converting bro logs in JSON form to csv format. The given JSON form is multi lines of json, so each line represents a JSON object. This script will also only accept logs from given ports (set as a constant), so as to decrease the scale of the data to interesting ports.
'''

# -- IMPORTS --
import argparse
import os
import json
import csv
from datetime import datetime, timedelta, timezone

# -------------

# -- CONSTANTS --
COL_NAMES = ["ts","uid","id.orig_h","id.orig_p","id.resp_h","id.resp_p","proto","service","duration","orig_bytes","resp_bytes","conn_state","local_orig","local_resp", "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes"]
PORTS = [22, 23, 80, 443, 445]

# ---------------

def get_dict(line):
    d = {}
    fields = line.split('\t')[:-1]
    for i, col in enumerate(COL_NAMES):
        if len(fields) <= i:
            d[col] = '-'
        else:
            d[col] = fields[i]
    return d

# Take in directory of bro logs as input.
parser = argparse.ArgumentParser()
parser.add_argument("--dir", type=str, dest="dir", default='../data/background/', help="The directory where the bro logs are located.")
args = parser.parse_args()
log_dir = args.dir

out_dir = log_dir
os.makedirs(out_dir, exist_ok=True)

print("\nList of files:", sorted(os.listdir(log_dir)))

days = {}
for bro_file_name in sorted(os.listdir(log_dir)):
    if not bro_file_name.endswith(".log"):
        continue
    print("Starting file: {}".format(bro_file_name))
    # Ignore non log files
    with open(os.path.join(log_dir, bro_file_name), 'r') as bro_file:
        i = 0
        lines = bro_file.readlines()
        for line in lines:
            if line.startswith('#'):
                continue
            i += 1
            if i % 10 ** 6 == 0:
                print("Completed processing {} logs in current file.".format(i))
            data = get_dict(line)
            # Filtering by port
            if int(data['id.resp_p']) in PORTS:

                dt = datetime.fromtimestamp(float(data['ts']))
                day = dt.strftime("%Y-%m-%d")
                data['ts'] = dt.replace(tzinfo=timezone.utc).timestamp()
                if day not in days:
                    days[day] = []
                days[day].append(data)
        print("Finished file: {}".format(bro_file_name))


for day in days:
    print("Writing for day: {}".format(day))

    out_file_name = os.path.join(out_dir, day, 'extracted_conn_features.csv')
    os.makedirs(os.path.join(out_dir, day), exist_ok=True)
    with open(out_file_name, 'w+', newline='') as out_file:
        logs = days[day]
        writer = csv.writer(out_file, delimiter=',')
        writer.writerow(COL_NAMES)
        for data in logs:
            # Writing data to the output csv
            writer.writerow([data.get(col, "-") for col in COL_NAMES])

        print("Written file: {}".format(out_file_name))

