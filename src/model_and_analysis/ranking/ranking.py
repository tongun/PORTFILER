'''
Functions used to compute and compare TOP_K KDE or IsolationForest scores for on different ports, in order to determine top ranked most anomalous time windows.
'''


# --- Imports ---
from sklearn.preprocessing import MinMaxScaler
import scipy.integrate as integrate
import pandas as pd
import numpy as np
import time
import os, sys
# add the parent directory to the path
sys.path.insert(0, os.path.abspath("../"))

from common import *
from constants import *
from constants_model import *
from model import *

# -----------------

# used for gathering performance metrics every top_k elements in the sorted anomaly scores list
TOP_K = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160, 170, 180, 190, 200, 250, 300, 350, 400, 450, 500, 550, 600, 650, 700, 750, 800, 900, 1000, 1100, 1200, 1300, 1400, 1440]

def get_top_k_scores(scores, k):
    score_tuples = [(v, i) for i, v in enumerate(scores)]
    scores_ranked = [(i, v) for (v, i) in sorted(score_tuples)]
    # scores_ranked = [(i, v) for (v, i) in sorted(score_tuples, reverse=True)]

    # print(scores_ranked[-10:-1])
    return scores_ranked[0:k]

def order_per_port(scores, port, prob_index=3):
    df = []
    for i in range(len(scores)):
        tuple_crt = scores[i]
        window = tuple_crt[0]
        val = tuple_crt[prob_index]
        row = [port, window, val]
        df.append(row)
        print(row)

    # print(df)
    return df


def write_scores_df(df, ports, out_file, across_all=True):
    col_headers = []
    if across_all:
        if MODEL == 'kde':
            col_headers = ["port", "window", "normalized_probability"]
        elif MODEL == 'isolation':
            col_headers = ["port", "window", "anomaly_score"]
    else:
        col_headers = ["port", "window", "score"]
    pd.DataFrame(df, columns=col_headers).to_csv(out_file, index=False)


def write_metrics(metrics, ports, out_file, across_all=True):
    df = []
    col_headers = []

    col_headers = ["k", "tp_total", "fp_total"]
    if across_all:
        for port in ports:
            fp_name = "fp_" + str(port)
            col_headers.append(fp_name)
        print(col_headers)

    for k in TOP_K:
        tp_values = metrics[0][k].values()
        fp_values = metrics[1][k].values()
        tp_total = sum(tp_values)
        fp_total = sum(fp_values)

        row = [k, tp_total, fp_total]

        if across_all:
            row = row + list(fp_values)
        
        df.append(row)

    print("df: ", df)

    pd.DataFrame(df, columns=col_headers).to_csv(out_file, index=False)
    

def get_topk_metrics(df_matrix, labels, ports, TOP_K):
    tp = dict() # true positives
    fp = dict() # false positives

    for k in TOP_K:
        tp[k] = dict()
        fp[k] = dict()
        for port in ports:
            tp[k][port] = 0
            fp[k][port] = 0
        
        count = 0
        for [port, win, val] in df_matrix:
            # print("labels[port][win]: ", labels[port][win], win)
            if labels[win]:
                tp[k][port] += 1
            else:
                fp[k][port] += 1
            count += 1
            if count == k: break

    print("tp, fp:", tp, fp)
    return tp, fp

def get_feature_str(feature_cols, feature_imp_str=None):
    if not feature_imp_str:
        if len(feature_cols) > 4:
            feature_str = str(len(feature_cols)) + "features"
        else:
            feature_str = '_'.join(feature_cols)
    else:
        features_str = feature_imp_str
    return feature_str






