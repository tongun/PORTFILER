'''
Compute and compare TOP_K kde and IsolationForest scores for different variants on different ports.
Getting alerts (anomalous time windows) for background traffic, without any malicious traffic inserted.
'''

# --- Imports ---
from sklearn.preprocessing import MinMaxScaler
import scipy.integrate as integrate
import pandas as pd
import numpy as np
import time
import os, sys
import argparse
# add the parent directory to the path
sys.path.insert(0, os.path.abspath("../../"))
sys.path.insert(0, os.path.abspath("../"))
sys.path.insert(0, os.path.abspath("../ensemble/"))

from common import *
from constants import *
from constants_model import *
from model import *
from ensemble_for_ranking import *
from ranking import *

WINDOWS_NUM = 1440 # 1-minute windows during a 24-hour period
NORMALIZATION = False # not using normalization in this experiment

# --- Main ---
if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("WEIGHTED", help="Type of ensemble, mean or weighted (False/True).")
    parser.add_argument("PORT_INFECTED", help="The infected port.")
    parser.add_argument("TEST_FILE", help="Location of the test file.")
    parser.add_argument("MODEL_DIR", help="Location of the single-feature models.")
    parser.add_argument("FEATURE_IMPORTANCE_DIR", help="Location of the feature importance coefficients.")
    parser.add_argument("OUTPUT_DIR", help="Location of the output dir.")
    args = parser.parse_args()
    print(args)

    OUTPUT_DIR = args.OUTPUT_DIR
    FEATURE_IMP_DIR = None 

    if args.WEIGHTED == "True":
        WEIGHTED = True
    else:
        WEIGHTED = False

    if WEIGHTED == True:
        # FEATURE_IMP_DIR needs to be point to the location of the feature importance coefficients
        FEATURE_IMP_DIR = args.FEATURE_IMPORTANCE_DIR

    PORT_INFECTED = int(args.PORT_INFECTED)
    TEST_FILE = args.TEST_FILE  # test file containig both background and malicious traffic
    MODEL_DIR = args.MODEL_DIR

    print("feature importance dir: ", FEATURE_IMP_DIR)
    print("port infected: ", PORT_INFECTED)

    print("\nFeature cols ranking merged ensemble:", FEATURE_COLS)
    print("\nFeature cols len:", len(FEATURE_COLS))

    # get the model; we usually use previously trained models
    feature_str = get_feature_str(FEATURE_COLS, feature_imp_str=None)
    print("Features, feature str:", FEATURE_COLS, feature_str)

    if not USE_SAVED_MODEL:
        print("Please train the model first")
        exit()

    # dictionaries of scores and results for each file (day)
    test_scores = []
    dir_scores = os.path.join(OUTPUT_DIR, "anomaly_scores")
    os.makedirs(dir_scores, exist_ok=True)

    port = PORT_INFECTED
    print("\nPort:", port)

    newf = os.path.join(dir_scores, "infected_p{}.obj".format(port))
    newfcsv = os.path.join(dir_scores, "infected_p{}.csv".format(port))
    #if os.path.exists(os.path.join(dir_scores, newf)): continue
    # with open(os.path.join(dir_scores, newf), mode='w'): pass
    print("Using test file: ", TEST_FILE)
    label_crt = True  #  if label_crt = True, get the ground truth labels for verification purposes

    scores_combined, Y = get_combined_scores_per_port(port, FEATURE_COLS, TEST_FILE, model_dir=MODEL_DIR, feature_imp_dir=FEATURE_IMP_DIR, weighted=WEIGHTED, labeled=label_crt, ranking=True, port_feat_imp=port)
    scores_topk = get_top_k_scores(scores_combined, WINDOWS_NUM)

    if MODEL == "kde":
        if NORMALIZATION:
            test_scores = normalize_top_scores(scores_topk, port, FEATURE_COLS, TEST_FILE, model_dir=MODEL_DIR, feature_imp_dir=FEATURE_IMP_DIR, weighted=WEIGHTED, port_feat_imp=port)
        else:
            test_scores = [tuple([elem[0], "N/A", elem[1]]) for elem in scores_topk]
        COL_NAMES_RANKING = ["window", "normalized score", "prob density score"]
    else:
        test_scores = scores_topk
        COL_NAMES_RANKING = ["window", "normalized score"]

    attack_windows = [i for i in range(len(Y)) if Y[i]]
    print("Number of attack windows:", len(attack_windows))
    print("Attack windows:", attack_windows)
    print("Scores for infected port:", test_scores)
    write_pickle(newf, test_scores)
    pd.DataFrame(test_scores, columns=COL_NAMES_RANKING).to_csv(newfcsv, index=False)
    print("Finished saving scores: ", newfcsv)

    write_pickle(os.path.join(dir_scores, "labels_infected_p{}.obj".format(PORT_INFECTED)), Y)
    print("Finished saving labels port infected: ", PORT_INFECTED)

# ------------
