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
import statistics
import argparse

# add the parent directory to the path
sys.path.insert(0, os.path.abspath("../../"))
sys.path.insert(0, os.path.abspath("../"))

from common import *
from constants import *
from constants_model import *
from ranking import *
# -----------------

WINDOWS_NUM = 1440

# --- Main ---
if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("PORT_INFECTED", help="The infected port.")
    parser.add_argument("OUTPUT_DIR", help="Location of the input/output dir.")
    args = parser.parse_args()
    print(args)

    PORT_INFECTED = int(args.PORT_INFECTED)
    OUTPUT_DIR = args.OUTPUT_DIR

    feature_str = get_feature_str(FEATURE_COLS, feature_imp_str=None)
    print("Features, feature str:", FEATURE_COLS, feature_str)

    # dictionaries of scores and results for each file (day)
    df_scores_sorted = dict()
    dir_scores = os.path.join(OUTPUT_DIR, "anomaly_scores")

    if MODEL == "kde":
        prob_index = 2 # use prob density directly, no normalization for the same port
    else:
        prob_index = 1

    port = PORT_INFECTED

    newf = "infected_p{}.obj".format(port)
    df_scores = read_pickle(os.path.join(dir_scores, newf))

    # these are the ground truth labels, used to compute performance metrics like false positives, etc.
    # they are not labels assigned by us after detection
    newl = "labels_infected_p{}.obj".format(port)
    Y = read_pickle(os.path.join(dir_scores, newl))
   
    attack_windows = [i for i in range(len(Y)) if Y[i]]
    print("\nPort:", port)
    print("len ground truth labels:", len(Y))
    print("Number of attack windows:", port, len(attack_windows))
    print("Attack windows:", attack_windows)
    print("Scores per port:", df_scores)

    # build and save the dataframe with top scores
    df_matrix = order_per_port(df_scores, port, prob_index) 
    print("df_matrix:", df_matrix)

    out_file_ranking = os.path.join(OUTPUT_DIR, "ranking", "ranking_p{}_{}.csv".format(port, feature_str))
    os.makedirs(os.path.dirname(out_file_ranking), exist_ok=True)
    write_scores_df(df_matrix, [port], out_file_ranking, across_all=False)        
    print("Finished saving ranking ", out_file_ranking)

    # compute performance metrics in top k
    metrics = get_topk_metrics(df_matrix, Y, [port], TOP_K)
    out_file_metrics = os.path.join(OUTPUT_DIR, "metrics", "metrics_p{}_{}.csv".format(port, feature_str))
    os.makedirs(os.path.dirname(out_file_metrics), exist_ok=True)
    write_metrics(metrics, [port], out_file_metrics, across_all=False)
    print("Finished printing metrics ", out_file_metrics)
    

# ------------
