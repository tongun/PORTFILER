# for each 1-minute window from the training data, apply the ensemble model to get the score. Sort the scores and find out what score s is at a specific percentile p. e.g., if p=10, it means that 10% of scores are <= than s  

# --- Imports ---
from sklearn.preprocessing import MinMaxScaler
import scipy.integrate as integrate
import pandas as pd
import numpy as np
import time
import os, sys

# add the parent directory to the path
sys.path.insert(0, os.path.abspath("../"))
sys.path.insert(0, os.path.abspath("ensemble/"))
sys.path.insert(0, os.path.abspath("ranking/"))

from common import *
from model import *
from ranking import *
from ensemble_for_ranking import *
from constants_model import *

WEIGHTED=True
FEATURE_IMP_DIR = "../data/results/feature_importance_coefficients/"

# --- Main ---
if __name__ == '__main__':
  
    print("\nFeature cols:", FEATURE_COLS)

    # get the model; we usually use previously trained models
    feature_str = get_feature_str(FEATURE_COLS, feature_imp_str=None)
    print("Features, feature str:", FEATURE_COLS, feature_str)

    if not USE_SAVED_MODEL:
        print("Please train the model first")
        exit()

    print("Model location: ", MODEL_DIR)
    print("Train directory: ", TRAIN_DIR)

    # dictionaries of scores and results for each file (day)
    df_scores = dict()
    dir_scores = SCORES_TRAINING_DIR
    dir_scores = os.path.join(dir_scores, "weighted_ensemble")
    os.makedirs(dir_scores, exist_ok=True)
    print("Output dir for scores in training: ", dir_scores)

    # get the train data
    train_files = sorted(os.listdir(TRAIN_DIR))
    train_files = [os.path.join(TRAIN_DIR, obj) for obj in train_files]
    train_files = [f for f in train_files if os.path.isfile(f)]

    print("Train files: ", train_files)

    for port in PORTS:
        print("\nPort:", port)

        scores_combined = np.asarray([])
        
        for crt_file in train_files:
            print("Train file: ", crt_file)
            scores_crt, _ = get_combined_scores_per_port(port, FEATURE_COLS, crt_file, model_dir=MODEL_DIR, feature_imp_dir=FEATURE_IMP_DIR, weighted=WEIGHTED, labeled=None, ranking=False, port_feat_imp=port)
            print("scores_crt: ", scores_crt)
            if len(scores_crt) == 0: continue
            scores_combined = np.concatenate((scores_combined, scores_crt), axis=None)

        percentiles = []
        thresh = [0.0, 0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9] + list(range(1, 101))
        for i in thresh:
            percentile_i = np.percentile(scores_combined, i, axis=None)
            percentiles.append(tuple([i, percentile_i]))

        scores_topk = get_top_k_scores(scores_combined, len(scores_combined))

        print("Len of scores: ", len(scores_combined))

        COL_NAMES_RANKING = ["window", "score"]
        COL_NAMES_PERCENTILES = ["percentile", "score"]

        newf = "scores_training_p{}.obj".format(port)
        newfcsv = "scores_training_p{}.csv".format(port)
        percentiles_csv = "percentiles_training_p{}.csv".format(port)

        newf = os.path.join(dir_scores, newf)
        newfcsv = os.path.join(dir_scores, newfcsv)
        percentiles_csv = os.path.join(dir_scores, percentiles_csv)

        write_pickle(newf, scores_topk)
        pd.DataFrame(scores_topk, columns=COL_NAMES_RANKING).to_csv(newfcsv, index=False)
        pd.DataFrame(percentiles, columns=COL_NAMES_PERCENTILES).to_csv(percentiles_csv, index=False)

        print("Finished saving scores: ", newfcsv)
        print("Finished saving percentiless: ", percentiles_csv)

# ------------
