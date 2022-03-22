'''
Creates evasive variants of wannacry bro logs
'''

import argparse
import pandas as pd
from random import getrandbits
from ipaddress import IPv4Address
import os
import pickle 

parser = argparse.ArgumentParser(description='Create new variant')
parser.add_argument('--input_dir', type=str, dest="input_dir", default="../data/wannacry/wannacry/")

args = parser.parse_args()
INPUT_DIR = args.input_dir
INPUT_FILE = 'conn_prepared.log'

VARIANTS = [2, 4, 8, 16, 256, 1024]  # means 1/n of the data is kept

PORTS = ['22', '23', '80', '443', '445']

history_dir = '../data/background/feature_extraction/history/'
HISTORY_FILES = (
history_dir + 'history_2011-08-12.obj',
history_dir + 'history_2011-08-13.obj')

def create_variant_files():
    '''
        New files named are created for each new variant
    '''

    print('Running for directory:', INPUT_DIR)

    variant_file = os.path.join(INPUT_DIR, INPUT_FILE)
    out_dfs = {}
    for variant in VARIANTS:
        # out_file = os.path.join(INPUT_DIR, str(variant)+INPUT_FILE)
        # file = open(out_file, 'w+')
        # file.close()

        out_dfs[variant] = [] # list of dicts to convert to df in the end

    print(out_dfs)

    original_df = pd.read_csv(variant_file, delimiter='\t', header=0)
    print('File read')
    internal_ips = set(original_df['id.orig_h'].tolist())
    #print(original_df)
    count_for_each_internal_ip = dict.fromkeys(internal_ips)
    for key in count_for_each_internal_ip:
        count_for_each_internal_ip[key] = 0
    print(count_for_each_internal_ip)

    ct = 0
    for index, row in original_df.iterrows():
        ct += 1
        internal_ip = row['id.orig_h']
        count_for_each_internal_ip[internal_ip] += 1
        count = count_for_each_internal_ip[internal_ip]
        for variant in VARIANTS:
            if count % variant == 0:
                out_dfs[variant].append(dict(row))
                #count_for_each_internal_ip[internal_ip] = 0
        if ct % 100000 == 0:
            print('row',ct)

    for variant in VARIANTS:
        out_file_for_variant = os.path.join(INPUT_DIR, str(variant)+INPUT_FILE)
        df = pd.DataFrame(out_dfs[variant])
        df = df.reindex( ['ts','uid','id.orig_h','id.orig_p','id.resp_h','id.resp_p','proto','service','duration',
                               'orig_bytes','resp_bytes','conn_state','local_orig','local_resp','missed_bytes',
                               'history','orig_pkts','orig_ip_bytes','resp_pkts','resp_ip_bytes','tunnel_parents'], axis=1)

        df.to_csv(out_file_for_variant,sep='\t', index=False)
        print('File written:', out_file_for_variant)
    print('Files written')


def get_history_ips(history_files=HISTORY_FILES):
    history_ips = dict.fromkeys(PORTS)
    for key in history_ips:
        history_ips[key] = []

    for i in range(len(history_files)):
        hfile = history_files[i]
        with open(hfile, 'rb') as f:
            history_for_day = pickle.load(f)
        for port in history_for_day:
            history_ips[port] += history_for_day[port]

    for port in history_ips:
        print('For port:', port)
        print('Len:', len(history_ips[port]))

    return history_ips


def create_variant_files_using_history():
    '''
        New files named are created for each new variant
    '''

    print('Running for directory:', INPUT_DIR)

    history_ips = get_history_ips()

    variant_file = os.path.join(INPUT_DIR, INPUT_FILE)
    original_df = pd.read_csv(variant_file, delimiter='\t', header=0)
    print('File read')
    internal_ips = set(original_df['id.orig_h'].tolist())
    # print(original_df)
    for port in PORTS:

        out_dfs = {}
        for variant in VARIANTS:
            out_dfs[variant] = []  # list of dicts to convert to df in the end

        print(out_dfs)

        count_for_each_internal_ip = dict.fromkeys(internal_ips)
        for key in count_for_each_internal_ip:
            count_for_each_internal_ip[key] = 0
        print(count_for_each_internal_ip)

        ct = 0
        for index, row in original_df.iterrows():
            ct += 1
            internal_ip = row['id.orig_h']
            count_for_each_internal_ip[internal_ip] += 1
            count = count_for_each_internal_ip[internal_ip]
            for variant in VARIANTS:
                if count % variant == 0:
                    out_dfs[variant].append(dict(row))
                    # count_for_each_internal_ip[internal_ip] = 0
                else:
                    row['id.resp_h'] = history_ips[port][ct % len(history_ips[port])]
                    out_dfs[variant].append(dict(row))
            if ct % 100000 == 0:
                print('row', ct)

        for variant in VARIANTS:
            out_file_for_variant = os.path.join(INPUT_DIR,
                                                'port_' + str(port) + '_history' + str(variant) + '_' + INPUT_FILE)
            df = pd.DataFrame(out_dfs[variant])
            df = df.reindex(
                ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto', 'service', 'duration',
                 'orig_bytes', 'resp_bytes', 'conn_state', 'local_orig', 'local_resp', 'missed_bytes',
                 'history', 'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes', 'tunnel_parents'], axis=1)

            df.to_csv(out_file_for_variant, sep='\t', index=False)
            print('File written:', out_file_for_variant)
            df = None
        print('Files written for port:', port)


create_variant_files()
create_variant_files_using_history()

