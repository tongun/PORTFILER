import sys
import os

# add the parent directory to the path
sys.path.insert(0, os.path.abspath("../"))

from constants import *

USE_SAVED_MODEL = True  # needs to be set to False for training a new model

# TRAIN_SINGLE_FEATURE is set to true for ensemble sigle-feature models, and false for multi-feature models
TRAIN_SINGLE_FEATURE = True # constant used when training a new model, and otherwise ignored

MODEL = "kde"  # isolation
PORTS = [22, 23, 80, 443]  # didn't have data for 445 in sample dataset
# PORTS = [23]  # didn't have data for 445 in sample dataset

# remove features that are redundant with num_conns if any
FEATURE_COLS = COL_HEADERS[2:]
FEATURES_TO_REMOVE = ['min_orig_bytes', 'min_resp_bytes', 'min_orig_pkts', 'min_resp_pkts', 'label']
FEATURE_COLS = [x for x in FEATURE_COLS if x not in FEATURES_TO_REMOVE]

SCALAR_BOUNDED = True
SCALER_MAX = 5  # multiplication factor to compute the upper bound on data range given to MinMaxScaler (times the max value seen in training)
SCALER_MIN = 0  # lower bound on data range given to MinMaxScaler

dir_path = os.path.dirname(os.path.realpath(__file__))
# TRAIN_DAYS = "2020-11-28_to_12-03"
TRAIN_DAYS = "2011-08-13"  # this string representing the days of training is part of the name of the model files from our "data" directory
TRAIN_DIR = os.path.join(dir_path, "../data/background/feature_extraction/features/train/")  # contains computed features for each day
MODEL_DIR = os.path.join(dir_path, "../data/models/"+MODEL+"/")  # model will be saved here

TEST_DIR = os.path.join(dir_path, "../data/background/feature_extraction/merged_conn_prepared_wannacry/")  # where the test files are located
TEST_FILE = "Test_Data_1024conn_prepared_2011-08-14.csv"
OUTPUT_DIR = os.path.join(dir_path, "../data/results/")  # the evaluation plots will be written here
SCORES_TRAINING_DIR = os.path.join(OUTPUT_DIR, "scores_training")

# the "WEIGHTED" parameter is set to False for mean ensemble method and True for the weighted ensemble
WEIGHTED=False

