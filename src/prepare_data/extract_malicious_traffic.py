'''
Converts the original wannacry bro logs into the format that is ready to merge with the background data.
'''

import argparse
import pandas as pd
from random import getrandbits
from ipaddress import IPv4Address
import os

parser = argparse.ArgumentParser(description='Extract malicious traffic, prepare for merging')
parser.add_argument('--input_dir', type=str, dest="input_dir", default="../data/wannacry/")

args = parser.parse_args()
INPUT_DIR = args.input_dir
INPUT_FILE = 'conn.log'
OUT_FILE = 'conn_prepared.log'
INTERNAL_PREFIX = '192.168.'
ATTACK_PORT = 445

WANNACRY_IPS = {'wannacry': ['192.168.1.114']}


def get_random_public_ip():
    '''
        Creates and returns a random global IPV4 address
        :returns | str : a random global IPV4 address
    '''
    while 1:
        bits = getrandbits(32)  # generates an integer with 32 random bits
        addr = IPv4Address(bits)  # instances an IPv4Address object from those bits
        if addr.is_global:  # checks if it is a global IP, retry if not
            break

    return str(addr)


def find_only_internal_sources(df):
    '''
    Returns the list of IPs that only communicate internally
    :param df:
    :return: list of ips
    '''
    internal_ips = set(df["id.orig_h"].tolist())
    keep_list = set()
    for i, row in df.iterrows():
        src = row["id.orig_h"]
        if src in keep_list:
            continue
        dst = row["id.resp_h"]
        if INTERNAL_PREFIX not in dst:
            internal_ips.remove(src)
            keep_list.add(src)

    return internal_ips


def convert_all_files():
    '''
        Converts all bro logs named INPUT_FILE in variant directories under INPUT_DIR.
        New files named OUT_FILE are created in each variant directory.
    '''

    for variant in os.listdir(INPUT_DIR):

        print('Running for directory:', variant)
        if variant not in WANNACRY_IPS:
            print('Directory not among the variants..Skipping')
            continue
        WANNACRY_IPS_FOR_SCENARIO = WANNACRY_IPS[variant]

        variant_file = os.path.join(INPUT_DIR, variant, INPUT_FILE)
        out_file = os.path.join(INPUT_DIR, variant, OUT_FILE)

        original_df = pd.read_csv(variant_file, delimiter='\t', header=None, skiprows=8)
        original_df.drop(original_df.tail(1).index,inplace=True) # drop last row

        cols = ['ts','uid','id.orig_h','id.orig_p','id.resp_h','id.resp_p','proto','service','duration',
                               'orig_bytes','resp_bytes','conn_state','local_orig','local_resp','missed_bytes',
                               'history','orig_pkts','orig_ip_bytes','resp_pkts','resp_ip_bytes','tunnel_parents']
        original_df.columns = cols
        original_df['ts'] = original_df['ts'].astype(float)
        original_df['id.resp_p'] = original_df['id.resp_p'].astype(int)
        original_df['id.orig_p'] = original_df['id.orig_p'].astype(int)

        # filter non-attack traffic
        malicious_df = original_df[original_df["id.orig_h"].isin(WANNACRY_IPS_FOR_SCENARIO)]
        malicious_df = malicious_df[malicious_df["id.resp_p"] == ATTACK_PORT]

        # remove nodes that only communicates internally
        int_ips_to_remove = find_only_internal_sources(malicious_df)
        malicious_df = malicious_df[~malicious_df["id.orig_h"].isin(int_ips_to_remove)]

        # replace internal-to-internal communication to internal-to-external
        src_ips = malicious_df["id.orig_h"].tolist()
        dst_ips = malicious_df["id.resp_h"].tolist()

        # for each internal IP, a different random IP corresponding to an internal destination should be generated
        random_ip_mapping = dict.fromkeys(src_ips)
        for key in random_ip_mapping:
            random_ip_mapping[key] = {}

        new_dst_ips = []
        for i, dst_ip in enumerate(dst_ips):
            if dst_ip.startswith(INTERNAL_PREFIX):
                src_ip = src_ips[i]

                if dst_ip not in random_ip_mapping[src_ip]:
                    random_ip_mapping[src_ip][dst_ip] = get_random_public_ip()

                new_dst_ips.append(random_ip_mapping[src_ip][dst_ip])

            else: # keep the original random IPs
                new_dst_ips.append(dst_ip)

        malicious_df["id.resp_h"] = new_dst_ips

        # replace timestamps
        malicious_df = malicious_df.sort_values(by=['ts'], ascending=True)
        times = malicious_df.ts.tolist()
        begin_ts = times[0]
        times_relative = [ts-begin_ts for ts in times]
        malicious_df.ts = times_relative

        malicious_df.to_csv(out_file,sep='\t', index=False)
        print('File written:', out_file)


convert_all_files()
