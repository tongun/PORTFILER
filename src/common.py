# Common utility functions

import pickle
from datetime import datetime, timedelta
import sys
import csv
import os


# reads a pickle file, returns contents
def read_pickle(filename):
    try:
        with open(filename, 'rb') as f:
            data = pickle.load(f)
        return data
    except IOError:
        return {}

# end read_pickle


# writes a pickle file
def write_pickle(filename, data):
    with open(filename, 'wb') as f:
        pickle.dump(data, f, protocol=pickle.HIGHEST_PROTOCOL)

# end write_pickle


# converts a  date interval from offset-aware to offset-naive
# e.g. From 20190611_00:30:00-01:00:00-0400 to [20190611_04:30:00, 20190611_05:00:00
def convert_time_interval_to_offset_naive(date_timestamp):
    date_str = date_timestamp.split("_")[0]

    time_str = date_timestamp.split("_")[1]
    time_1 = time_str[0:8]
    time_2 = time_str[9:17]
    offset = time_str[17:22]
    offset_hours = int(offset[1:3])
    offset_mins = int(offset[3:5])

    print("date str: ", date_str, time_1, time_2, offset_hours)

    dt_1 = datetime.strptime(date_str + " " + time_1, '%Y%m%d %H:%M:%S')
    dt_2 = datetime.strptime(date_str + " " + time_2, '%Y%m%d %H:%M:%S')

    if offset[0] == '+':
        print("This is Eastern US time, expected to be behind UTC, not after. Error!")
        exit()

    # add the offset to convert to UTC
    # necessary to make them offset-naive, like in the json file (to be able to compare them)
    time_start_utc = dt_1 + timedelta(hours=offset_hours, minutes=offset_mins)
    time_end_utc = dt_2 + timedelta(hours=offset_hours, minutes=offset_mins)

    if time_2 == "00:00:00":  # this is beginning of next day
        time_end_utc = time_end_utc + timedelta(hours=24)

    print("UTC time:", time_start_utc, time_end_utc)
    print("Eastern Time:", dt_1, dt_2)
    return [time_start_utc, time_end_utc, dt_1, dt_2]


def float_to_datetime(fl):
    return datetime.fromtimestamp(fl)


def datetime_to_float(d):
    return d.timestamp()


def check_file_exists(file_path):
    if not os.path.isfile(file_path):
        print("File " + file_path + " does not exist!")
        exit()


def apply_time_offset(ts, time_end_sec, time_start_sec, ts_offset):
    offset = ts_offset * (time_end_sec - time_start_sec)
    new_ts = ts + offset
    if new_ts > time_end_sec:
        print("Dropping wannacry traffic, ts_offset too large")
        sys.stdout.flush()
        return None

    return new_ts



