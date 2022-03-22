'''
Processes a sequence of bro log files in csv format and convert them to usable feature files.
This is a top-level file that calls functions from logs_to_features.py to generate features.
For details on features generated please see logs_to_features.py
'''

# --- Imports ---
import os
import argparse
import csv
import time
import sys
import pdb
from datetime import datetime, timedelta
import numpy as np
import pandas as pd

# add the parent directory to the path
# sys.path.insert(0, os.path.abspath("../src/"))
sys.path.insert(0, os.path.abspath("../"))

from common import *
from constants import TW_LEN
from construct_history import *
from logs_to_features_labeled import *
# ---------------


# --- Constants ---

LOGS_BY_DAY = True  # full day folders
RELATE_TO_PREV = False  # relate to previous history; will not construct history base

LOG_DIR = "../data/background"


LOG_FILES = { # log files on rivanna
    '2011-08-12': ['extracted_conn_features.csv', 0],
    '2011-08-13': ['extracted_conn_features.csv', 0],
    '2011-08-14': ['extracted_conn_features.csv', 1]
}

# OUT_DIR_BASE = "../data/uva/"
OUT_DIR_BASE = os.path.join(LOG_DIR, "feature_extraction")
print("OUT_DIR_BASE for features:", OUT_DIR_BASE)

# -----------------

# --- Main ---

# create output directory structure:
# data/timestamp/{features, objs, history}
OUT_DIR = OUT_DIR_BASE
out_dir_features = os.path.join(OUT_DIR, "features")
out_dir_objs = os.path.join(OUT_DIR, "objs")
out_dir_history = os.path.join(OUT_DIR, "history")
out_dir_subnets = os.path.join(OUT_DIR, "subnets")
os.makedirs(out_dir_features, exist_ok=True)
os.makedirs(out_dir_objs, exist_ok=True)
os.makedirs(out_dir_history, exist_ok=True)
os.makedirs(out_dir_subnets, exist_ok=True)

if not RELATE_TO_PREV:
    # generate history base, as the first day in the list
    history_base = min(LOG_FILES.keys())
    print("HISTORY_BASE_DAY: ", history_base)
    log_file = os.path.join(LOG_DIR, history_base, LOG_FILES[history_base][0])
    out_file_history = os.path.join(out_dir_history, "history_{}.obj".format(history_base))
    print("Time 1 start hist base: ", int(datetime.now().timestamp()))
    read_csv_and_construct_history(log_file, out_file_history)
    print("Time 2 end hist base: ", int(datetime.now().timestamp()))

# generate features, history and obj files for each of the other days, in order
# processing days in consecutive order is important for correct history generation

history_files = []

if not RELATE_TO_PREV:
    days = sorted(LOG_FILES.keys())[1:]
else:
    days = sorted(LOG_FILES.keys())[0:]
    history_files_past = sorted(os.listdir(DIR_HISTORY_PAST))[:-1] # only the days used in training
    history_files += [os.path.join(DIR_HISTORY_PAST, obj) for obj in history_files_past]

history_files_crt = sorted(os.listdir(out_dir_history))
history_files += [os.path.join(out_dir_history, obj) for obj in history_files_crt]

print("Days: ", days)
for day in days:
    log_file = os.path.join(LOG_DIR, day, LOG_FILES[day][0])

    if LOGS_BY_DAY:
        day_str = day
    else:
        day_str = "1"

    out_file = os.path.join(out_dir_features, "ExtractedFeaturesWindow{}_{}.csv".format(TW_LEN, day_str))
    out_file_history = os.path.join(out_dir_history, "history_{}.obj".format(day_str))
    out_file_subnets = os.path.join(out_dir_subnets, "subnets_{}.obj".format(day_str))
    if LOG_FILES[day][1] == 1:
        out_file_obj = os.path.join(out_dir_objs, "data_accumulated_{}.obj".format(day_str))
    else: out_file_obj = None

    print("Time 1 start day : ", day, int(datetime.now().timestamp()))
    read_csv_and_extract_features(log_file, history_files, out_file, out_file_history, out_file_subnets, out_file_obj, logs_by_day=LOGS_BY_DAY)
    print("Time 2 end day : ", day, int(datetime.now().timestamp()))

