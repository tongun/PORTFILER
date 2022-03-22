'''
Evaluates a model on test data and produces ROC and Precision-Recall graphs. All ports use the same set of features.
'''

# --- Imports ---
import pandas as pd
import os, sys

# add the parent directory to the path
sys.path.insert(0, os.path.abspath("../"))

from constants_model import *
from model import *
# ---------------


def train_and_save_model(features, train_data):
    if TRAIN_SINGLE_FEATURE:
        model_file_name = os.path.join(MODEL_DIR, "{}_{}_model_{}.obj".format(features[0], TRAIN_DAYS, MODEL))
    else:
        model_file_name = os.path.join(MODEL_DIR, "{}features_{}_model_{}.obj".format(len(features), TRAIN_DAYS, MODEL))
        
    get_model(model_file_name, train_data, features)


# --- Main ---

if __name__ == '__main__':

    if USE_SAVED_MODEL:
        raise ValueError("Set USE_SAVED_MODEL=False before training")

    # get the train data
    train_files = sorted(os.listdir(TRAIN_DIR))
    train_files = [os.path.join(TRAIN_DIR, obj) for obj in train_files]

    # train_files = [os.path.join(TRAIN_DIR, obj) for obj in train_files][:1]  # use only first file for now
    print("Train files: ", train_files)

    train_data = pd.concat([pd.read_csv(f) for f in train_files])
    print("Train data:", train_data)

    print("\nFeature cols:", FEATURE_COLS)
    
    # save the model for future testing
    os.makedirs(MODEL_DIR, exist_ok=True)

    # single feature training
    if TRAIN_SINGLE_FEATURE:
        for f in FEATURE_COLS:
            train_and_save_model([f], train_data)
    else:
        train_and_save_model(FEATURE_COLS, train_data)

    print("Finished training model.")
# ------------
