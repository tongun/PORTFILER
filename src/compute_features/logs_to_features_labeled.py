'''
This script converts the bro log files in csv format to usable feature files. The features it will create are the following:

    - Distinct external IP per port (done)
    - Number of new distinct external IPs per port with history (done)
    - Number of connections per port (done)
    - Number of internal IPs per port
    - Mean, min, max duration time per port.
    - Mean, min, max number of bytes and packets sent
    - Mean, min, max number of response bytes and packets
    - Count of each connection state string

'''

# --- Imports ---
import os
import copy
import time
import sys
import pandas as pd
import pytz

# add the parent directory to the path
sys.path.insert(0, os.path.abspath("../"))

from common import *
from constants import TW_LEN, TW_PER_DAY, PORTS, COL_HEADERS, CONNECTION_STATES
# ---------------
# --- Constants ---


LOCATION = "uva"  # used to determine which IP is internal

# Data structure: [set(external_ips), num_conns, unique_external_ips(based on history)
#set(internal ips), [min_duration, max_duration, num_durations, sum_durations, duration_variance], orig_bytes_stats, resp_bytes_stats, orig_pkts_stats, resp_pkts_stats]
FEATURE_BASE = [set(), 0, 0, set(), [float("inf"), -1, 0, 0, 0],[float("inf"), -1, 0, 0, 0],[float("inf"), -1, 0, 0, 0],[float("inf"), -1, 0, 0, 0],[float("inf"), -1, 0, 0, 0]]
# Connection state features, count for each state
FEATURE_BASE.append([0] * len(CONNECTION_STATES))
FEATURE_BASE.append([0, 0])  # number of failed connections, number of connections with zero response bytes
FEATURE_BASE.append(0)  # number of malicious connections per window
# -----------------

# --- Functions ---
def read_csv_and_extract_features(log_file, history_files, out_file, out_file_history, out_file_subnets, out_file_obj=None, logs_by_day=True):
    '''
    Main function essentially. Loops through given csv file,
    extracts the desired features, writes these features to an output file in the given directory.
    :param log_file | str : The location of the log file to read
    :param history_files | [str] : The list of history file names, one for each of the previous days that constitute the history
    :param out_file | str : The location to write the output file to
    :param out_file_history | str : The location of the history file that is generated for the current day
    :param out_file_obj | str : The location on the intermediary object file that will be used to merge with wannacry traffic;
                                only relevant for the day used in testing
    '''
    print("\nExtracting features.")
    print("Log file: ", log_file)
    print("History files: ", history_files)
    print("Output features file: ", out_file)
    print("Output history file: ", out_file_history)
    print("Output subnets file: ", out_file_subnets)
    if out_file_obj: print("Output obj file: ", out_file_obj)

    print("TW_LEN, TW_PER_DAY:", TW_LEN, TW_PER_DAY)
    data = [{port: copy.deepcopy(FEATURE_BASE) for port in PORTS} for i in range(TW_PER_DAY)]
    crt_history = {port: set() for port in PORTS}
    history = initialize_history(history_files)
    subnets = dict() # dictionary with distinct internal IPs per subnets /24

    if logs_by_day:
        day = datetime.strptime(log_file.split(os.sep)[-2], "%Y-%m-%d")
    else:
        day = False

    with open(log_file, 'r') as in_file:
        reader = csv.DictReader(in_file, delimiter=',')
        i = 0
        cur = time.time()
        for row in reader:
            if row['id.resp_p'] not in PORTS:
                # print("continue 1: ", row['id.resp_p'], PORTS)
                continue
            data = update_data(row, data, day, history, crt_history, subnets)
            i += 1
            if i % 10 ** 6 == 0:
                print("Total processed: {}, time per {}: {}".format(i, 10 ** 6, time.time() - cur))
                cur = time.time()

    if out_file_obj: write_pickle(out_file_obj, data)

    write_pickle(out_file_history, crt_history)
    write_pickle(out_file_subnets, subnets)
    # print("data:", data)
    data_featurized = featurize_data(data)
    # print("featurized:", data_featurized)

    write_data(data_featurized, out_file)
    print("Finished extracting features")


def initialize_history(history_files):
    '''
    Reads a list of history files and saves data into a in-memory data structure
    It returns a list of daily dictionaries, where each dictionary maintains distinct external IPs per port
    :param history_files | [str] : A list of history files
    :returns | [{port -> set(distinct external ips)}]
    '''
    history = [dict() for i in range(len(history_files))]
    for i in range(len(history_files)):
        hfile = history_files[i]
        if not os.path.isfile(hfile):
            print("History file ", hfile, " not valid.")
            sys.exit(0)
        history[i] = read_pickle(hfile)
    return history


def update_data(row, data, day, history, crt_history, subnets):
    '''
    Updates the given data object using the row data provided.
    :param row | {colname -> value} : The row of data from the bro logs.
    :param data | [timewindow -> {port -> [features]}] : The features to udpate given the new data
    :param day | date : Current day
    :param history | [{port -> set(distinct_ext_ips)}] : The history of the previous days
    :param crt_history | [{port -> set(distinct_ext_ips)}] : The history of the current day, being built
    :returns | [timewindow -> {port -> [features]}] : The updated data
    '''
    #if row['anon_orig'] == row['anon_resp']:
    #    # print("not int to int")
    #    return data # Don't want internal->internal, ext->ext
    if ':' in row['id.orig_h'] or ':' in ['id.resp_h']:
        return data
    
    ts_dt = datetime.fromtimestamp(float(row['ts']), tz=pytz.UTC)
    row_dt = ts_dt.astimezone(tz=pytz.timezone('US/Eastern')) 

    if day and row_dt.date() != day.date():
        # print("not same day")
        return data
    cur_window = get_window_by_datetime(row_dt)
    port = row['id.resp_p']

    # print("cur_window, port: ", cur_window, port) 
    data[cur_window][port] = update_features(row, data[cur_window][port], history, crt_history, subnets)
    # print("data: ", data[cur_window][port])

    return data

def get_window_by_datetime(dt):
    return ((dt.hour * 60 + dt.minute) * 60 + dt.second) // TW_LEN

def update_features(row, features, history, crt_history, subnets):
    '''
    Updates the features given the new row data
    :param row | {colname -> value} : The row data used to update the features.
    :param features | [features] : The features to update.
    :param history | [{port -> set(distinct_ext_ips)}] : The history of the previous days
    :param crt_history | [{port -> set(distinct_ext_ips)}] : The history of the current day, being built
    :returns | [features] : The updated features.
    '''

    if row['id.orig_h'].startswith('147.32'):
        int_ip, ext_ip = row['id.orig_h'], row['id.resp_h']
    else:
        int_ip, ext_ip = row['id.resp_h'], row['id.orig_h']

    # ensuring compatibility with both old and new values of "anon" fields
    # use above code instead, this is not correct when traffic from uva to vt
    # if row['anon_orig'] == "False" or row['anon_orig'] == "none":
    #    int_ip, ext_ip = row['id.resp_h'], row['id.orig_h']
    # else:
    #     int_ip, ext_ip = row['id.orig_h'], row['id.resp_h']
    port = row['id.resp_p']
    duration = row['duration']
    orig_bytes = row['orig_bytes']
    resp_bytes = row['resp_bytes']
    orig_pkts = row['orig_pkts']
    resp_pkts = row['resp_pkts']
    conn_state = row['conn_state']
    label_str = 'background'
    mal = 0
    if label_str.startswith("malicious"):
        mal = 1

    is_new = update_new_ips(ext_ip, port, history, crt_history)
    subnets = update_subnets(subnets, int_ip)
    # print("row: ", row)
    # print("is_new: ", is_new)

    features[0].add(ext_ip)
    features[3].add(int_ip)
    features[4] = update_statistical_features(features[4], float(duration)) if duration != "-" else features[4]
    features[5] = update_statistical_features(features[5], float(orig_bytes)) if orig_bytes != "-" else features[5]
    features[6] = update_statistical_features(features[6], float(resp_bytes)) if resp_bytes != "-" else features[6]
    features[7] = update_statistical_features(features[7], float(orig_pkts)) if orig_pkts != "-" else features[7]
    features[8] = update_statistical_features(features[8], float(resp_pkts)) if resp_pkts != "-" else features[8]
    features[9] = update_conn_state_features(features[9], conn_state) if conn_state != "-" else features[9]
    features[10] = update_unsuccessful_conn_features(features[10], conn_state, resp_bytes)
    features[11] = features[11] + mal  # number of malicious connections per window

    # print("features: ", features)

    return [features[0],
            features[1] + is_new,
            features[2] + 1,
            features[3],
            features[4], features[5], features[6], features[7], features[8], features[9], features[10], features[11]]

def update_conn_state_features(features, new_val):
    '''
    Updates a list of count features for the connection states
    :param features | [num] : List of count for each state
    :param new_val | num : The new value to be processed to update the features
    :returns | [num] : The updated count features
    '''
    if new_val not in CONNECTION_STATES:
        raise ValueError("could not find %s in CONNECTION_STATES" % (new_val))

    features[CONNECTION_STATES.index(new_val)] += 1
    return features

def update_unsuccessful_conn_features(features, new_conn_state, new_resp_bytes):
    '''
    Updates the counts for failed connections and connections with zero response bytes
    '''
    if new_conn_state not in ['-', 'S1', 'SF']:
        features[0] += 1
    if new_resp_bytes != '-' and float(new_resp_bytes) == 0:
        features[1] += 1
    return features

def update_statistical_features(features, new_val):
    '''
    Updates a list of statistical features of the following form:
        [min, max, count, sum, variance]
    :param features | [num] : The aformentioned list of statistical features
    :param new_fal | num : The new value to be processed to update the features
    :returns | [num] : The updated statistical features
    '''
    features = [min(features[0], new_val),
            max(features[1], new_val),
            features[2] + 1,
            features[3] + new_val,
            features[4]]

    # See welford's algorithm: https://en.wikipedia.org/wiki/Algorithms_for_calculating_variance#Welford's_online_algorithm
    features[4] = welfords(features[2], features[3], features[4], new_val)
    return features

def welfords(n, n_sum, prev_variance, new_val):
    '''
    Uses welford's algorithm to compute the variance update.
    :param n | int : The new n (count)
    :param n_sum | float : The sum of all values up to n
    :param prev_variance | float : The previous variance
    :param new_val | float : The new value used to update the variance
    :return | float : The sample variance at n
    '''
    if n > 1:
        mean_n_1 = (n_sum - new_val) / (n - 1)
        mean_n = n_sum/n
        new_variance = prev_variance + ((new_val - mean_n_1) * (new_val - mean_n) - prev_variance)/n
    else:
        new_variance = 0
    return new_variance

def update_new_ips(ext_ip, port, history, crt_history):
    '''
    Checks the history to see if a given IP has been seen before.
    If this is a new IP, it is added to the current day's history.
    :param ext_ip | str : External IP
    :param port | str : Port
    :param history | [{port -> set(distinct_ext_ips)}] : The history of the previous days
    :param crt_history | [{port -> set(distinct_ext_ips)}] : The history of the current day, being built
    :returns is_new | int : Returns 1 if the IP is new, and 0 otherwise
    '''
    is_new = 0
    
    for history_day in history:
        if port not in history_day: 
            continue
        if ext_ip in history_day[port]:
            return is_new

    if ext_ip not in crt_history[port]:
        crt_history[port].add(ext_ip)
        is_new = 1
    return is_new

def update_subnets(subnets, ip):
    '''
    Reads the first 3 bytes of an IP and updates the subnets dictionary if this IP has not been seen before
    :param subnets | {subnet -> set(internal  IPs)} The /24 subnets
    :param ip | str : IP (internal)
    :returns subnets | {subnet -> set(internal 	IPs)} Return dictionary with distinct internal IPs per subnet
    '''
    subnet_24 = '.'.join(ip.split('.')[0:3]) + '.'

    if subnet_24 not in subnets:
        subnets[subnet_24] = set()
    subnets[subnet_24].add(ip)
    return subnets


def mean_convert(feature_stats):
    '''
    Converts the count and sum to mean in feature stats
    :param feature_stats | [min, max, count, sum, variance] : The feature stats to return
    :returns [min, max, mean, variance] : The mean converted stats
    '''
    if feature_stats[2] == 0:
        # If nothing was sampled, all should be 0
        return [0, 0, 0, 0]
    return [feature_stats[0], feature_stats[1], feature_stats[3] / feature_stats[2], feature_stats[4]]

def featurize_data(data):
    '''
    Converts the data to featurized data.
    :param data | [timewindow -> {port -> [features]}] : The unfeaturized data
    :returns | [feature] : The featurized data
    '''
    featurized_data = []
    for timewindow in range(TW_PER_DAY):
        for port in data[timewindow]:
            cur_features = data[timewindow][port]
            # print("cur_features:", cur_features)
            if cur_features == FEATURE_BASE: 
                # print("same feature base")
                continue
            label = True if (cur_features[11] > 0) else False

            # print("mal and label: ", cur_features[11], label)
            out_features = [timewindow, port, len(cur_features[0]),
                    cur_features[1], cur_features[2], len(cur_features[3])] + mean_convert(cur_features[4]) + \
                           mean_convert(cur_features[5]) + mean_convert(cur_features[6]) + \
                           mean_convert(cur_features[7]) + mean_convert(cur_features[8]) + \
                           cur_features[9] + cur_features[10] + [label]
            featurized_data.append(out_features)
    return featurized_data


def write_data(data_featurized, out_file):
    '''
    Writes the given data to the output file.
    :param data_featurized | [feature] : The data to write
    :param out_file | str : The path to the file to write
    '''

    COL_HEADERS1 = COL_HEADERS + ['label']
    print("COL_HEADERS1: ", COL_HEADERS1)
    pd.DataFrame(data_featurized, columns=COL_HEADERS1).to_csv(out_file, index=False)
# -------------
