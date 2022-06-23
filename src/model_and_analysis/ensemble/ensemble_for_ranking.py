'''
Evaluates an ensemble model composed of aggregated single-feature models on test data and produces ROC and Precision-Recall graphs. Loops through a set of features, using a single feature at a time and combines the scores into an aggregated score either by 1) taking the mean (Mean Ensemble), or 2) taking an weighted mean (Weighted Ensemble). The weighted ensemble requires apriori knowledge of the feature weights. 
'''

# --- Imports ---
import pandas as pd
import numpy as np
import os, sys
import time
from sklearn.metrics import precision_score, recall_score, precision_recall_curve, roc_curve
import statistics
import scipy.integrate as integrate

# add the parent directory to the path
sys.path.insert(0, os.path.abspath("../../"))
sys.path.insert(0, os.path.abspath("../"))
sys.path.insert(0, os.path.abspath("../ranking/"))

from common import *
from constants_model import *
from model import *
# ---------------

def kde_normalize_all_scores(kde, x_vals):
    scores_norm = []
    for x in x_vals:
        ccdf = kde_ccdf(kde, x)
        scores_norm.append(ccdf)
    return scores_norm

def kde_cdf(kde, x):
    cdf = kde_integrate_quad(kde, -np.inf, x)[0]
    # print("x, cdf: ", x, cdf)
    return cdf

def kde_ccdf(kde, x):
    cdf = kde_cdf(kde, x)
    return 0.0 if cdf > 1.0 else 1.0 - cdf

def kde_integrate_quad(kde, xmin, xmax):
    kde_fct = lambda x: np.exp(kde.score_samples(np.array([x]).reshape(-1,1)))[0]    
    return integrate.quad(kde_fct, xmin, xmax, epsabs=1.49e-20)

def kde_cdf(kde, x):
    cdf = kde_integrate_quad(kde, -np.inf, x)[0]
    # print("x, cdf: ", x, cdf)
    return cdf

def print_statistics(scores_dict, ports):
    for port in ports:
        print("\n\nport:", port)

        res = [list(x) for x in zip(*scores_dict[port].values())]
        means = [statistics.mean(x) for x in res]
        print("\n\nmean:", means)
        # stds = [statistics.pstdev(x) for x in res]
        stds = [statistics.stdev(x) for x in res]
        print("\n\nstd:", stds)

def combine_scores_by_mean(scores_dict):
    res = [list(x) for x in zip(*scores_dict.values())]
    # print("res, len:", len(res), res)
    means = [statistics.mean(x) for x in res]
    # print("\n\nmean:", means)
    return means

def read_feature_importance(port, feature_imp_dir):
    filename = os.path.join(feature_imp_dir, "port{}.csv".format(port))
    data = pd.read_csv(filename, header=None, sep='\s+', index_col=0)
    print(data)
    return data

def apply_weights(feature_importance, scores_dict, feature_cols):
    fsum = 0
    sum_weights = 0
    for f in feature_cols:
        first_column = feature_importance.iloc[:, 0]
        if f not in first_column: 
            continue

        index = feature_cols.index(f)
        feat_imp_f = feature_importance.loc[f, 1]
        fsum += feat_imp_f * scores_dict[index]
        sum_weights += feat_imp_f
    print("sum_weights, fsum:", sum_weights, fsum)
    return fsum / sum_weights 


def combine_scores_by_imp(scores_dict, port, feature_imp_dir, feature_cols):
    print("combining scores: ", port, feature_imp_dir)
    feature_imp = read_feature_importance(port, feature_imp_dir)

    res = [list(x) for x in zip(*scores_dict.values())]
    # print("res, len:", len(res), res)
    weighted_scores = [apply_weights(feature_imp, x, feature_cols) for x in res]
    print("\n\nweighted_scores:", weighted_scores)
    return weighted_scores


def get_combined_scores_per_port(port, feature_cols, t_file, model_dir=None, feature_imp_dir=None, weighted=True, labeled=True, ranking=False, port_feat_imp=None):
    scores_dict = dict()
    Y = []
    
    for feat in feature_cols:
        # print("Testing on feature: ", feat)

        # read the model
        model_file_name = os.path.join(model_dir, "{}_{}_model_{}.obj".format(feat, TRAIN_DAYS, MODEL))
        models = get_model(model_file_name, None, [feat])
        if port not in models: 
            return [], [] 

        scores_dict[feat] = dict()

        scaler, model = models[port]
        test_data = pd.read_csv(t_file)
        test_data = test_data[test_data['port'] == port]
        if len(test_data) == 0:
            return [], []

        if labeled:
            Y = test_data['label'].values
        else:
            Y = [False for i in range(len(test_data))]
        # print("Y: ", Y)

        # compute model scores for the feature columns of interest
        X = test_data.filter([feat]).values
        # print("X: ", X)
        # print("Testing: port,  min, max, mean, std: ", port, X.min(), X.max(), X.mean(), X.std())
        if SCALAR_BOUNDED:
            X = bound_test_data(scaler, X, [feat])

        X = scaler.transform(X)

        if MODEL == "isolation":
            scores = model.score_samples(X)
        else:
            scores = np.exp(model.score_samples(X))

        scores_dict[feat] = scores
        print("\n\nport, scores, len, type: ", port, len(scores), type(scores), scores)
        # print_statistics(scores_dict, PORTS)

    if weighted:
        scores_combined = np.asarray(combine_scores_by_imp(scores_dict, port_feat_imp, feature_imp_dir, feature_cols))
        print("\n\nScores combined by feature imp: ", len(scores_combined), type(scores_combined), scores_combined)
    else:
        scores_combined = np.asarray(combine_scores_by_mean(scores_dict))
        print("\n\nScores combined by mean: ", len(scores_combined), type(scores_combined), scores_combined)
    return scores_combined, Y


def normalize_top_scores(scores_topk, port, feature_cols, t_file, model_dir=None, feature_imp_dir=None, weighted=True, port_feat_imp=None):

    scores_dict = dict()
    scores_final = []

    # print("scores_topk: ", scores_topk)

    windows_topk = [elem[0] for elem in scores_topk]
    print("windows_topk: ", windows_topk) 
    scores_only_topk = [elem[1] for elem in scores_topk]
    print("scores_only_topk: ", scores_only_topk) 

    for feat in feature_cols:
        # print("Testing on feature: ", feat)

        # read the model
        # model_file_name = os.path.join(model_dir, "{}_{}_model_{}.obj".format(feat, TRAIN_DAYS, MODEL))
        models = get_model(model_file_name, None, [feat])

        scores_dict[feat] = dict()

        scaler, model = models[port]
        test_data = pd.read_csv(t_file)
        test_data = test_data[test_data['port'] == port]

        test_data = pd.DataFrame({'timewindow':windows_topk}).merge(test_data)
        # test_data = test_data[test_data.timewindow.isin(windows_topk)]
        print(test_data)

        # compute model scores for the feature columns of interest
        X = test_data.filter([feat]).values
        # print("Testing: port,  min, max, mean, std: ", port, X.min(), X.max(), X.mean(), X.std())
        if SCALAR_BOUNDED:
            X = bound_test_data(scaler, X, [feat])

        X = scaler.transform(X)

        scores_before = np.exp(model.score_samples(X))
        # scores_dict[feat] = scores
        # print("\n\nport, scores, len, type: ", port, len(scores), type(scores), scores)

        print("Total area under kde curve, approx 1: ", kde_integrate_quad(model, -np.inf, np.inf)) # approximates to 1
        print("scores before norm:", scores_before)
        scores_norm = kde_normalize_all_scores(model, X)
        scores_dict[feat] = np.array(scores_norm)

    if weighted:
        scores_combined = np.asarray(combine_scores_by_imp(scores_dict, port_feat_imp, feature_imp_dir, feature_cols))
        print("\n\nScores combined by feature imp: ", len(scores_combined), type(scores_combined), scores_combined)
    else:
        scores_combined = np.asarray(combine_scores_by_mean(scores_dict))
        print("\n\nScores combined by mean: ", len(scores_combined), type(scores_combined), scores_combined)

    for i in range(len(scores_combined)):
        scores_final.append(tuple([windows_topk[i], scores_combined[i], scores_only_topk[i]]))

    return scores_final


# ------------

