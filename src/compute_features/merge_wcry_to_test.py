'''
Merges one wannacry variant into one day of background data at a given offset to create features and labels for testing.
'''

# --- Imports ---

import sys, os
import pandas as pd
import ipaddress
import random

sys.path.insert(0, os.path.abspath("../"))

from common import *
from constants import *

# ---------------

# --- Constants ---
MERGE_ALL = True
MERGE_DAY = "2011-08-14"

DATA_DIR = "../data/background/feature_extraction"
OUT_DIR = os.path.join(DATA_DIR, "merged_conn_prepared_wannacry")
os.makedirs(OUT_DIR, exist_ok=True)

FEATURE_FILE = os.path.join(DATA_DIR, "objs", "data_accumulated_" + MERGE_DAY + ".obj")
HISTORY_DIR = os.path.join(DATA_DIR, "history")
SUBNETS_DIR = os.path.join(DATA_DIR, "subnets")

WCRY_DIR = '../data/wannacry/wannacry/'

# -----------------

# --- Functions ---
def read_wannacry_logs(wcry_file, history_files, ip_mappings):
    '''
    Reads wannacry logs and converts them to features object at timewindows
    (for features that don't depend on a port-based history, no port is necessary, all traffic will be merged onto 1 port)
    :param wcry_file | str : The path to the wannacry logs
    :returns | [timewindow -> [features]], [timewindow -> features_hist] :
    '''
    print("Reading and updating features for wcry: ", wcry_file)
    crt_history = {port: set() for port in PORTS}
    history = initialize_history(history_files)
    wc_data = pd.read_csv(wcry_file, delimiter='\t', header=0, engine='python', index_col=False)
    min_ts = datetime.fromtimestamp(min(wc_data['ts']))
    out_data = [[set(), 0, set(), [], [], [], [], [], [0] * len(CONNECTION_STATES), [0, 0]] for i in range(TW_PER_DAY)]

    # out_data_hist is keeping track of number of new distinct ext IPs relative to the history per port
    out_data_hist = [{port: 0 for port in PORTS} for i in range(TW_PER_DAY)]
    print(len(wc_data))
    for line in wc_data.iterrows():
        out_data, out_data_hist = update_data(line[1], out_data, out_data_hist, min_ts, 
                                              history, crt_history, ip_mappings)

    return out_data, out_data_hist


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


def update_data(row, data, data_hist, min_ts, history, crt_history, ip_mappings):
    '''
    Updates the given data object using the row data provided.
    :param row | {colname -> value} : The row of data from the bro logs.
    :param data | [timewindow -> [features]] : The features to udpate given the new data
    :param min_ts | datetime : The lowest datetime in the wannacry data
    :param history | [{port -> set(distinct_ext_ips)}] : The history of the previous days
    :param crt_history | [{port -> set(distinct_ext_ips)}] : The history of the current day, being built
    :returns | [timewindow -> [features]], [timewindow -> features_hist] : The updated data
    '''

    cur_window = get_window(datetime.fromtimestamp(row['ts']), min_ts)
    data[cur_window], data_hist[cur_window] = update_features(  row,
                                                                data[cur_window],
                                                                data_hist[cur_window],
                                                                history, crt_history,
                                                                ip_mappings)
    return data, data_hist

def get_window(ts, min_ts):
    '''
    Get's the proper window given the timestamp
    :param ts | datetime : The timestamp
    :param min_ts | datetime : The lowest ts
    :returns | int : The timewindow to use
    '''
    return ((ts - min_ts).seconds // TW_LEN) + OFFSET_TW


def update_features(row, features, features_hist, history, crt_history, ip_mappings):
    '''
    Updates the features given the new row data
    :param row | {colname -> value} : The row data used to update the features.
    :param features | [features] : The features to update.
    :param features_hist | [features] : The features that depend on a per-port history.
    :param history | [{port -> set(distinct_ext_ips)}] : The history of the previous days
    :param crt_history | [{port -> set(distinct_ext_ips)}] : The history of the current day, being built
    :returns | [features], features_hist : The updated features.
    '''

    int_ip, ext_ip = row['id.orig_h'], row['id.resp_h']
    int_ip_saved = int_ip
    int_ip = ip_mappings[int_ip]
    # print("This ip {} is mapped to {}".format(int_ip_saved, int_ip))

    features[0].add(ext_ip)
    features[2].add(int_ip)
    # Keeping track of all duration due to the structure of this file.
    # In the future if we don't have an aggregate -> merge strucutre, we can do online here too

    duration = [float(row['duration'])] if row['duration'] != '-' else []
    orig_bytes = [float(row['orig_bytes'])] if row['orig_bytes'] != '-' else []
    resp_bytes = [float(row['resp_bytes'])] if row['resp_bytes'] != '-' else []
    orig_pkts = [float(row['orig_pkts'])] if row['orig_pkts'] != '-' else []
    resp_pkts = [float(row['resp_pkts'])] if row['resp_pkts'] != '-' else []
    state = [row['conn_state']] if row['resp_pkts'] != '-' else []
    
    features[8][CONNECTION_STATES.index(state[0])] += 1
    features[9] = update_unsuccessful_conn_features(features[9], row['conn_state'], row['resp_bytes']) 

    features = [features[0],
                features[1] + 1,
                features[2],
                features[3] + duration,
                features[4] + orig_bytes,
                features[5] + resp_bytes,
                features[6] + orig_pkts,
                features[7] + resp_pkts,
                features[8],
                features[9]]

    for port in PORTS:
        is_new = update_new_ips(ext_ip, port, history, crt_history)
        features_hist[port] += is_new

    return features, features_hist

def update_unsuccessful_conn_features(features, new_conn_state, new_resp_bytes):
    '''
    Updates the counts for failed connections and connections with zero response bytes
    '''
    if new_conn_state not in ['-', 'S1', 'SF']:
        features[0] += 1
    if new_resp_bytes != '-' and float(new_resp_bytes) == 0:
        features[1] += 1
    return features

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
        if ext_ip in history_day[port]:
            return is_new

    if ext_ip not in crt_history[port]:
        crt_history[port].add(ext_ip)
        is_new = 1
    return is_new

def merge_wannacry_features(wc_data, wc_data_hist, nw_data):
    '''
    Merges wannacry feature object with given feature object. Merges on every port
    :param wc_data | [tw -> [features]] : The wannacry data to merge
    :param wc_data_hist | [tw -> features] : The history-based wannacry data to merge
    :param nw_data | [tw -> {port -> [features]}] : The network data to merge into
    :returns | [timewindow -> {port -> [features]}] : The data to write
    '''

    # some auxiliary code to get the propagation rate (IPs per minute)
    sum_ips = 0.0
    count = 0
    for tw in range(TW_PER_DAY):
        if wc_data[tw] != [set(), 0, set(), [], [], [], [], [], [0] * len(CONNECTION_STATES), [0, 0]]:
            count += 1 
            sum_ips += len(wc_data[tw][0])

    avg_ips = sum_ips / count
    print("Ips per min:", avg_ips, sum_ips, count, TW_PER_DAY)
    # exit()

    print("len data: ", len(wc_data), len(wc_data_hist), len(nw_data))
    for tw in range(TW_PER_DAY):
        # print("tw: ", tw)
        nw_data[tw] = merge_wc_at_tw(wc_data[tw], wc_data_hist[tw], nw_data[tw])

    return nw_data

def merge_wc_at_tw(wc_at_tw, wc_at_tw_hist, nw_at_tw):
    '''
    Merges wannacry data at the given timewindow into the nw data. Merges on every port.
    :param wc_at_tw | [features] : The wc features at the given timewindow
    :param wc_at_tw_hist | {port -> feature} : The wc feature (history-based, per port) at the given tw
    :param nw_at_tw | {port -> [features]} : The network data at the timewindow
    :returns | {port -> [features]} : The new network data at this timewindow
    '''
    return {port: [nw_at_tw[port][0].union(wc_at_tw[0]),
                   nw_at_tw[port][1] + wc_at_tw_hist[port],
                   nw_at_tw[port][2] + wc_at_tw[1],
                   nw_at_tw[port][3].union(wc_at_tw[2]),
                   merge_stats_all(nw_at_tw[port][4], wc_at_tw[3]),
                   merge_stats_all(nw_at_tw[port][5], wc_at_tw[4]),
                   merge_stats_all(nw_at_tw[port][6], wc_at_tw[5]),
                   merge_stats_all(nw_at_tw[port][7], wc_at_tw[6]),
                   merge_stats_all(nw_at_tw[port][8], wc_at_tw[7]),
                   merge_state_counts(nw_at_tw[port][9], wc_at_tw[8]),
                   merge_unsuccessful_conns(nw_at_tw[port][10], wc_at_tw[9])]
                   for port in PORTS}

def merge_state_counts(nw_counts_array, wc_counts):
    '''
    Merges all the state counts from wanancry into the statistical features.
    :param nw_stats_array | [int] : state counts in background data
    :param wc_counts | [int] : state counts from wc durations
    :returns | [int] : New state counts
    '''

    new_counts = [nw_counts_array[i] + wc_counts[i]  for i in range(len(nw_counts_array))]
    return new_counts

def merge_unsuccessful_conns(nw_counts_array, wc_counts):
    new_counts = [nw_counts_array[i] + wc_counts[i]  for i in [0, 1]]
    return new_counts

def merge_stats_all(nw_stats_array, wc_durations):
    '''
    Merges all the durations from wanancry into the statistical features.
    :param nw_stats_array | [stat] : The stats as described in `logs_to_features.py`
    :param wc_durations | [float] : All the durations at this timewindow from wannacry
    :returns | [stat] : The min, max, mean, variance of duration merged
    '''

    for duration in wc_durations:
        nw_stats_array = update_statistical_features(nw_stats_array, duration)
    return nw_stats_array

def mean_convert(feature_stats):
    '''
    Converts the count and sum to mean in feature stats
    :param feature_stats | [min, max, count, sum, variance] : The feature stats to return
    :returns [min, max, mean, variance] : The mean converted stats
    '''
    if feature_stats[2] == 0:
        # If nothing was sampled, min and max should be 0
        return [0,0,0,0]
    return [feature_stats[0], feature_stats[1], feature_stats[3] / feature_stats[2], feature_stats[4]]

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

def get_wcry_timewindows(wcry_data):
    '''
    Gets the timewindows where wannacry was active, for labeling.
    :param wcry_data | [timewindow -> [features]] : The wannacry data in feature form
    :returns | [timewindow] : The timewindows wanancry was active
    '''

    return [i for i in range(TW_PER_DAY) if wcry_data[i] != [set(), 0, set(), [], [], [], [], [], [0] * len(CONNECTION_STATES), [0, 0]]]

def featurize_data(data, labels):
    '''
    Converts the data to featurized data.
    :param data | [timewindow -> {port -> [features]}] : The unfeaturized data
    :returns | [feature] : The featurized data
    '''
    featurized_data = []
    for timewindow in range(TW_PER_DAY):
        for port in data[timewindow]:
            cur_features = data[timewindow][port]
            out_features = [timewindow, port, len(cur_features[0]),
                    cur_features[1], cur_features[2], len(cur_features[3])]
            # Adding all the statistical features
            for stat_ind in range(4, 9):
                out_features += mean_convert(cur_features[stat_ind])
            out_features += cur_features[9]
            out_features += cur_features[10]
            out_features.append(timewindow in labels)
            featurized_data.append(out_features)
    return featurized_data


def write_data(data_featurized, out_file):
    '''
    Writes the given data to the output file.
    :param data_featurized | [feature] : The data to write
    :param out_file | str : The path to the file to write
    '''
    pd.DataFrame(data_featurized, columns=COL_HEADERS_TEST).to_csv(out_file, index=False)


def merge_one_variant(wcry_log_file, wc_var, feature_file, history_files, output_directory, ip_mappings):
    '''
    Top-level function, executes the entire merging of one variant
    '''
    day = os.path.splitext(feature_file)[0].split("_")[-1]
    print("Day: ", day)
    print("Wcry log file: ", wcry_log_file) 

    wc_data, wc_data_hist = read_wannacry_logs(wcry_log_file, history_files, ip_mappings)
    wc_timelabels = get_wcry_timewindows(wc_data)
    given_features = read_pickle(feature_file)
    out_data = merge_wannacry_features(wc_data, wc_data_hist, given_features)
    featurized_data = featurize_data(out_data, wc_timelabels)
    output_file = os.path.join(output_directory, "Test_Data_{}_{}.csv".format(wc_var, day))
    write_data(featurized_data, output_file)
    print("Finished merging, result in ", output_file)


def merge_all_variants(wcry_dir, wcry_file_name, wannacry_ips,
                       feature_file, history_files, output_directory,
                       subnets, selected_subnets, wcry_by_rate = None):
    '''
    Top level-function, executes the merging of multiple wannacry variants
    '''
    if wcry_by_rate: wc_var = wcry_by_rate

    subfolders = [f.path for f in os.scandir(wcry_dir) if f.is_dir() ]
    for sf in subfolders:
        wcry_log_file =os.path.join(sf, wcry_file_name)
        if not wcry_by_rate: wc_var = sf.split(os.sep)[-1]
        print(wcry_log_file, wc_var)

        ip_mappings = map_wc_ips_to_subnets(wannacry_ips[wc_var], subnets, selected_subnets)
        merge_one_variant(wcry_log_file, wc_var, feature_file, history_files, output_directory, ip_mappings)


def find_subnets(subnets,
                 network,
                 max_num_wc_ips=10,
                 num_variants=15):
    '''
    randomly select subnets on the network;
    selected subnets are /24;
    these subnets will be used for mapping of wannacry internal IPs
    '''

    subnets_list = list(subnets.keys())
    selected_subnets = set()

    trys = 0
    while trys < 1000 and len(selected_subnets) < num_variants:
        # todo: infinite looping?
        # randomly select subnets
        subnet = random.choice(subnets_list)

        # complete the IP address with the last byte
        subnet_full_addr = subnet + "0"

        # only select subnets on the network, and which have enough IPs
        if ipaddress.ip_address(subnet_full_addr) in ipaddress.ip_network(network) \
                and len(subnets[subnet]) >= max_num_wc_ips:
            selected_subnets.add(subnet_full_addr)

        trys += 1


    if trys == 1000:
        print('try reached')
        exit()
    return selected_subnets


def map_wc_ips_to_subnets(wannacry_ips, subnets, selected_subnets):
       # the IPs in this file will be mapped to the following subnet
        subnet = selected_subnets.pop()
        subnet_str = subnet[0:-1]  # remove last byte, it is 0
        print("subnet to map to: ", subnet)

        # randomly select the background IPs to map to
        num_wc_ips = len(wannacry_ips)
        print("Number of wannacry IPs: ", num_wc_ips)

        selected_ips = random.sample(subnets[subnet_str], num_wc_ips)
        print("IPs to map to: ", selected_ips)
        # map wannacry IPs to background IPs
        ip_mappings = dict()
        for j in range(num_wc_ips):
            ip_mappings[wannacry_ips[j]] = selected_ips[j]
        print("IP mappings: ", ip_mappings)
        return ip_mappings

def select_subnets(subnets_dir, day,
                         network,
                         max_num_wc_ips=10,
                         num_variants=15):
    # get the /24 subnets from background data
    subnets_file = os.path.join(subnets_dir, 'subnets_' + day + '.obj')
    print("\nLoading subnets /24 (list of distinct ips for each subnet) from: ", subnets_file)
    subnets = read_pickle(subnets_file)

    # find a number of "num_variants" subnets which have at least "num_wannacry_machines" internal IPs
    # on the given network
    selected_subnets = find_subnets(subnets, network, max_num_wc_ips, num_variants)

    print("Selected subnets to use for mapping: ", selected_subnets)
    return subnets, selected_subnets


def update_subnets(subnets, subnets_24, s):
    '''
    Reads the first 2 bytes of an IP and updates the subnets dictionary if this IP has not been seen before
    :param subnets | {subnet -> set(internal  IPs)} The /16 subnets
    :param ip | str : IP (internal)
    :returns subnets | {subnet -> set(internal  IPs)} Return dictionary with distinct internal IPs per subnet
    '''
    subnet_16 = '.'.join(s.split('.')[0:2]) + '.'

    if subnet_16 not in subnets:
        subnets[subnet_16] = [0, 0]  # count of /24 and count of ips
    subnets[subnet_16][0] += 1
    subnets[subnet_16][1] += len(subnets_24[s])
    return subnets

def find_network(subnets_dir, day, num_variants):
    # get the /24 subnets from background data
    subnets_file = os.path.join(subnets_dir, 'subnets_' + day + '.obj')
    print("\nLoading subnets /24 (list of distinct ips for each subnet) from: ", subnets_file)
    subnets_24 = read_pickle(subnets_file)
    sub_24_len = dict()
    for s in subnets_24:
        sub_24_len[s] = len(subnets_24[s])
    sorted_y = sorted(sub_24_len.items(), key=lambda sub_24_len: sub_24_len[1], reverse=True)
    print("sub /24:", sorted_y)

    subnets_16 = dict()
    for s in subnets_24:
        subnets_16 = update_subnets(subnets_16, subnets_24, s)    
    # sort by number of ips
    sorted_x = sorted(subnets_16.items(), key=lambda subnets_16: subnets_16[1][1], reverse=True)
    print("sub /16:", sorted_x)
    
    network = sorted_x[3][0] + "0.0/16"
    print("network:", network)
    return network
    

# -----------------
'''
parser = argparse.ArgumentParser()
parser.add_argument("feature_file", help="Path to the feature object file.")
parser.add_argument("output_directory", help="The location to output the merged traffic as features.")
parser.add_argument("wcry_log_file", help="The location of the wannacry log file to use")

args = parser.parse_args()
feature_file = args.feature_file
output_directory = args.output_directory
wcry_log_file = args.wcry_log_file
history_files = HISTORY_FILES
print(args.wcry_log_file)
'''

wcry_dir = WCRY_DIR
feature_file = FEATURE_FILE
history_dir = HISTORY_DIR
subnets_dir = SUBNETS_DIR
output_directory = OUT_DIR

day = os.path.splitext(feature_file)[0].split("_")[-1]
if day != MERGE_DAY:
    print("Feature file needs to match merge day!")
    exit()

print("merge day: ", day)

history_files_all = sorted(os.listdir(history_dir))
history_files_all = [os.path.join(history_dir, obj) for obj in history_files_all]

history_files = []
for hist_file in history_files_all:
    hist_day = os.path.splitext(hist_file)[0].split("_")[-1]
    if hist_day <= MERGE_DAY:
        history_files.append(hist_file)

print("history files: ", history_files)

# if wcry_dir ends with "/" need to remove if because variant will be empty string
if wcry_dir[-1] == '/': wcry_dir = wcry_dir[:-1]
variant = wcry_dir.split(os.sep)[-1]
if '/' in variant: variant = variant.split('/')[-1]
print("wcry_dir:", wcry_dir)
print("Offset:", OFFSET_TW)
print("variant:", variant)

if variant.startswith("wannacry"):  # process single variant
    wc_variants_count = 1
else: # process entire directory
    wc_variants_count = WC_VARIANTS_COUNT

print("\nMake sure to set the correct LOCATION in merge_wcry_to_test.py!!!\n")

subnets, selected_subnets = select_subnets(subnets_dir, day, NETWORK, WC_IPS_MAX_COUNT, wc_variants_count)



if MERGE_ALL:
    print("MERGE_ALL")

    ip_mappings = map_wc_ips_to_subnets(WANNACRY_IPS[variant], subnets, selected_subnets)
    for f in sorted(os.listdir(wcry_dir)):
        # Ignore non log files
        if not f.endswith("_prepared.log"):
            continue
        print("Starting file: {}".format(f))
        wc_var = f[:-4]
        print("Variant vm by rate: ", wc_var)
        wcry_log_file =os.path.join(wcry_dir, f)
        merge_one_variant(wcry_log_file, wc_var, feature_file, history_files, output_directory, ip_mappings)

elif variant in WANNACRY_IPS:
    print("single variant: ", variant)
    wcry_log_file =os.path.join(wcry_dir, WCRY_FILE_NAME)
    print("wcry log file:", wcry_log_file)
    ip_mappings = map_wc_ips_to_subnets(WANNACRY_IPS[variant], subnets, selected_subnets)
    merge_one_variant(wcry_log_file, variant, feature_file, history_files, output_directory, ip_mappings)



