'''
Constants that are to be used across multiple files that should be imported.
'''

TW_LEN = 60 # The length of a time window in seconds
TW_PER_DAY = 24 * 60 * 60 // TW_LEN # The total number of timewindows in a day
PORTS = ['22', '23', '80', '443', '445']

COL_HEADERS = ['timewindow', 'port', 'external_ips', 'new_external_ips', 'num_conns', 'internal_ips', 'min_duration', 'max_duration', 'mean_duration', 'variance_duration',
        'min_orig_bytes', 'max_orig_bytes', 'mean_orig_bytes', 'variance_orig_bytes',
        'min_resp_bytes', 'max_resp_bytes', 'mean_resp_bytes', 'variance_resp_bytes',
        'min_orig_pkts', 'max_orig_pkts', 'mean_orig_pkts', 'variance_orig_pkts',
        'min_resp_pkts', 'max_resp_pkts', 'mean_resp_pkts', 'variance_resp_pkts',
        'S0_count', 'S1_count', 'SF_count', 'REJ_count', 'S2_count', 'S3_count', 'RSTO_count',
        'RSTR_count', 'RSTOS0_count', 'RSTRH_count', 'SH_count', 'SHR_count', 'OTH_count',
        'failed_conn_count','zero_resp_bytes_count']

CONNECTION_STATES = ['S0', 'S1', 'SF', 'REJ', 'S2', 'S3', 'RSTO', 'RSTR', 'RSTOS0', 'RSTRH', 'SH', 'SHR', 'OTH']
COL_HEADERS_TEST = COL_HEADERS + ['label']
WCRY_HEADERS=["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents"]
WCRY_SUBNET = '192.168.'
OFFSET=0.5
OFFSET_TW = int(OFFSET * TW_PER_DAY)
WCRY_FILE_NAME = "conn_prepared.log"

NETWORK = "147.32.0.0/16" # local

WC_IPS_MAX_COUNT = 1 # maximum number of infected wannacry IPs per variant
WC_VARIANTS_COUNT = 1 # number of wannacry variants

WANNACRY_IPS = {
    'mirai': ['192.168.1.198'],
    'hajime': ['192.168.100.111'],  # 23, 81
    'kenjiro': ['192.168.100.111'],  # 8081, 37215, 80, 81
    'wannacry': ['192.168.1.114']
}


