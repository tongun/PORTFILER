'''
    This script's purpose is to create the history base. It reads the bro log files in csv format and generates the following:

    - {PORT: set(distinct external IP in history)}
'''

# --- Imports ---
import os
import csv
import time
from datetime import datetime

from common import *
from constants import PORTS

# ---------------

# --- Functions ---
def read_csv_and_construct_history(log_file, out_file_history):
    '''
    Main function essentially. Loops through given csv file,
    extracts the desired features, writes these features to an output file in the given directory.
    :param log_file | str : The location of the log file to read
    :param out_file | str : The location to write the output file to
    '''
 
    print("LOG_FILE:", log_file)
    print("History file created:", out_file_history)

    day = datetime.strptime(log_file.split(os.sep)[-2], "%Y-%m-%d")
    print(day)
    data = {port: set() for port in PORTS}
    with open(log_file, 'r') as in_file:
        reader = csv.DictReader(in_file, delimiter=',')
        i = 0
        cur = time.time()
        for row in reader:
            if row['id.resp_p'] not in PORTS: 
                continue
            data = update_data(row, data, day)
            i += 1
            if i % 10 ** 6 == 0:
                print("Total processed: {}, time per {}: {}".format(i, 10 ** 6, time.time() - cur))
                cur = time.time()
              
    write_pickle(out_file_history, data)
    print("Finished creating history.")


def update_data(row, data, day):
    '''
    Updates the given data object using the row data provided.
    :param row | {colname -> value} : The row of data from the bro logs.
    :param data | {port -> ext_ips} : Distinct external IPs
    :returns | {port -> ext_ips} : The updated data
    '''

    #if row['anon_orig'] and row['anon_resp']:
    #    return data # Don't want internal->internal, ext->ext

    if ':' in row['id.orig_h'] or ':' in ['id.resp_h']:
        return data

    row_dt = datetime.fromtimestamp(float(row['ts'])) 
    if row_dt.date() != day.date():
        return data
    port = row['id.resp_p']
    data[port] = update_set_ips(row, data[port])

    return data


def update_set_ips(row, set_ips):
    '''
    Updates the set of IPs given the new row data
    :param row | {colname -> value} : The row data used to update the history.
    :param set_ips | set(ip) : The set of IPs to update.
    :returns | set(ip) : The updated set of IPs.
    '''
    # ensuring compatibility with both old and new values of "anon" fields
    # if row['anon_orig'] == "False" or row['anon_orig'] == "none": ext_ip = row['id.orig_h']
    # else: ext_ip = row['id.resp_h']
    
    if row['id.orig_h'].startswith('147.32'):
        int_ip, ext_ip = row['id.orig_h'], row['id.resp_h']
    else:
        int_ip, ext_ip = row['id.resp_h'], row['id.orig_h']

    set_ips.add(ext_ip)
    return set_ips

