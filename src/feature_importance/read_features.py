'''
Functions for getting the data from the feature columns of interest.
'''

from numpy import *
import pandas as pd
import os
import csv

# some legacy features, but not useful
FEATURES_TO_REMOVE = ['min_orig_bytes', 'min_resp_bytes', 'min_orig_pkts', 'min_resp_pkts']

def get_feature_names(f, training_dir):
    columns = get_column_names(f, training_dir)
    columns = [x for x in columns if x not in FEATURES_TO_REMOVE]
    return columns[2:-1]

def get_column_names(f, training_dir):
    file_name = os.path.join(training_dir, f)
    with open(file_name, 'r') as f:
        reader = csv.reader(f, delimiter=',')
        header = next(reader)

    header = [x for x in header if x not in FEATURES_TO_REMOVE]
    return header


def read_features(training_dir, training_files, port):

    feature_cols = get_column_names(training_files[0], training_dir)
    print("features, and number of features: ", feature_cols, len(feature_cols))

    # get the data
    feature_files = [os.path.join(training_dir, obj) for obj in training_files]
    print("Feature files: ", feature_files)

    data = pd.concat([pd.read_csv(f) for f in feature_files])
    # print("Data:", data)

    data = data[data['port'] == port].filter(items=feature_cols).to_numpy()
    # print("Data after filtering, number of columns:", len(feature_cols))
    # print(data)

    data_X = data[:, 2:-1].tolist()
    data_Y = data[:, -1].tolist()

    # print("\nData_X: ", data_X)
    # print("\nData_Y: ", data_Y)

    return data_X, data_Y




