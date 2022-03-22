'''
Provides fuctions to train a model (KDE and IsolationForest) on multi class data for predicting which windows of network traffic are anomalous.
'''
# --- Imports ---
from sklearn.neighbors.kde import KernelDensity
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import f1_score, make_scorer, precision_score, recall_score, confusion_matrix, auc
from sklearn.model_selection import GridSearchCV 
import statsmodels.api as sm
import numpy as np
import os
from common import *
from constants_model import *
# ---------------

# --- Functions ---
def train_model(data, port, feature_cols):
    '''
    Trains the KDE model for the training data on the given port.
    :param data | DataFrame : The training data to use
    :param port | int : The port to train on
    :param feature_cols | [str] : List of features to use in training
    :param bandwidth | num : The bandwidth to use in training
    :return | Scaler, KernelDensity : A fit scaler for the data, and a fit kernel density model
    '''
    print("Training on col, port: ", feature_cols, port)
    data = data[data['port'] == port].filter(items=feature_cols).values

    print("Data after filtering, number of columns:", len(feature_cols), feature_cols)
    print(data)
    scaler = MinMaxScaler()
    
    if SCALAR_BOUNDED:
        scaler, data = set_scaler_bounds(scaler, data, feature_cols)
    else:
        data = scaler.fit_transform(data)
    print("Final scaled features:", data)

    if MODEL == 'multi_bw':
        model = sm.nonparametric.KDEMultivariate(data=data, bw='cv_ml', var_type='cc')
        print("port:{}".format(port), " bandwidth: {0}".format(model.bw))
    elif MODEL == "isolation":
        if len(feature_cols) > 20:
            max_features_param = [10, 15] + list(range(16, len(feature_cols) + 1, 1))
        else:
            max_features_param = [len(feature_cols)]

        print("max features param: ", max_features_param)
        params = {'n_estimators': [50],
                  'max_samples': [100],
                  'contamination': ['auto'],
                  'max_features': max_features_param,
                  'bootstrap': [True]}

        print("Searching isolation forest...")

        grid = GridSearchCV(IsolationForest(random_state=123, behaviour='new'), params, cv=2, iid=False, scoring=lambda estimator, X: np.mean(estimator.score_samples(X)))
        grid.fit(data)
        model = grid.best_estimator_
        print("port: {}, n_estimators: {}, max_samples: {}, contamination: {}, max_features: {}, bootstrap: {}".format(port, model.n_estimators, model.max_samples, model.contamination, model.max_features, model.bootstrap))

    else:  # KDE
        params = {'bandwidth': np.linspace(0, 1, 50)}
        grid = GridSearchCV(KernelDensity(), params, cv=2, iid=False)
        grid.fit(data)
        model = grid.best_estimator_
        print("port:{}".format(port), " bandwidth: {0}".format(model.bandwidth))
    return scaler, model

def set_scaler_bounds(scaler, data_f, feature_cols):

    data_f = data_f.astype(float)
    new_bounds = np.empty([2, len(feature_cols)])
    
    for i in range(len(feature_cols)):
        data = data_f[:,i]
        print(data)
        new_min_max = [SCALER_MIN, SCALER_MAX * data.max()]
        new_bounds[:,i] = new_min_max

    data_f = np.append(data_f, new_bounds, axis = 0)
    data_f = scaler.fit_transform(data_f)
    data_f = data_f[:-2, :]

    return scaler, data_f


def bound_test_data(scaler, X, feature_cols):
    for i in range(len(feature_cols)):
        X_i = X[:, i]
        X_i[X_i > scaler.data_max_[i]] = scaler.data_max_[i]
    return X


def print_stats(preds, labels):
    '''
    Prints the accuracy, recall, precision, and f1 scores for the given predictions and labels.
    :param preds | [int] : The predictions from the model.
    :param labels | [int] : The ground truth labels.
    '''
    print("----------\nAccuracy: {}, Precision: {}, Recall: {} F1: {}".format(sum(preds == labels) / len(labels),
            precision_score(labels, preds), recall_score(labels, preds), f1_score(labels, preds)))


def compute_thresh_fpr_tpr(scores, labels):
    '''
    Gets the true and false positive rates based on the given scores and labels.
    Use this function if list of thresholds has not been gives, and compute thresholds on-the-fly.
    :param scores | [float] : The predicted likelihoods of being a malicious time window.
    :param labels | [bool] : The ground truths
    :returns | ([float], [float]) : The list of fpr and tpr
    '''
    min_score = min(scores)
    max_score = max(scores)
    # The minimum and maximum scores for positive labels.
    min_pos = min(scores[labels == True])
    max_pos = max(scores[labels == True])
    if max_pos >= max_score:
        # Making it so arange works. Shouldn't matter for ROC/AUC
        max_score =  max_pos + 0.00001
    if min_pos == max_pos:
        min_pos -= 0.00001
    if min_pos <= min_score:
        min_score = min_pos - 0.00001
    print("{} {} {} {}".format(min_score, min_pos, max_pos, max_score))
    thresholds = np.concatenate((
            np.arange(min_score, min_pos, (min_pos - min_score) / 100),
            np.arange(min_pos, max_pos, (max_pos - min_pos) / 100),
            np.arange(max_pos, max_score, (max_score - max_pos) / 100)))
    return list(zip(* ([get_fpr_tpr(scores < thresh, labels) for thresh in sorted(thresholds)] + [(1, 1)])))


def get_fpr_tpr_list(scores, labels, thresholds=None):
    '''
    Gets the true and false positive rates based on the given scores and labels.
    :param scores | [float] : The predicted likelihoods of being a malicious time window.
    :param labels | [bool] : The ground truths
    :returns | ([float], [float]) : The list of fpr and tpr
    '''
    print("\nActual attack windows:", [i for i in range(len(labels)) if labels[i]])
    return list(zip(* ([(0, 0)] + [get_fpr_tpr(scores <= thresh_abs(scores, thresh), labels, thresh) for thresh in sorted(thresholds)])))

def get_prec_recall_list(scores, labels, thresholds=None):
    '''
    Gets the true and false positive rates based on the given scores and labels.
    :param scores | [float] : The predicted likelihoods of being a malicious time window.
    :param labels | [bool] : The ground truths
    :returns | ([float], [float]) : The list of fpr and tpr
    '''
    return list(zip(* ([(1, 0)] + [get_prec_recall(scores <= thresh_abs(scores, thresh), labels, thresh) for thresh in sorted(thresholds)])))

def thresh_abs(scores, thresh):
    return min(scores) + thresh * (max(scores) - min(scores))

def get_fpr_tpr(preds, labels, thresh):
    '''
    Gets the true positive rate and false positive rate given the predictions and labels.
    :param preds | [bool] : The predicted labels
    :param labels | [bool] : The ground truth
    :returns | (float, float) : The fpr and tpr
    '''
    # print("\nPredictions:", [i for i in range(len(preds)) if preds[i]])
    tpr = recall_score(labels, preds)
    tn, fp, fn, tp = confusion_matrix(labels, preds).ravel()
    print("Thresh, tn, fp, fn, tp: ", thresh, tn, fp, fn, tp)
    return ((fp / (fp + tn)), tpr)

def get_prec_recall(preds, labels, thresh):
    '''
    Gets the true positive rate and false positive rate given the predictions and labels.
    :param preds | [bool] : The predicted labels
    :param labels | [bool] : The ground truth
    :returns | (float, float) : The fpr and tpr
    '''
    # print("\nPredictions:", [i for i in range(len(preds)) if preds[i]])
    tn, fp, fn, tp = confusion_matrix(labels, preds).ravel()
    prec = (tp / (tp + fp))
    recall = (tp / (tp + fn))
    if recall !=  recall_score(labels, preds):
        print("Recall is different!!")
        exit()

    print("Thresh={} tn={}, fp={}, fn={}, tp={}, prec={}, recall={}".format(thresh, tn, fp, fn, tp, prec, recall))
    return (prec, recall)

def get_confusion_matrix_metrics(scores, labels, thresholds=None):
    metrics_list = []
    for thresh in sorted(thresholds):
        tn, fp, fn, tp = confusion_matrix(labels, scores <= thresh_abs(scores, thresh)).ravel()
        metrics_list.append([thresh, tn, fp, fn, tp])

    print("Metrics: Thresh, tn, fp, fn, tp: ", metrics_list)
    return metrics_list

def get_model(model_file_name, train_data, feature_cols):

    if not USE_SAVED_MODEL: # train and save model for later use
        print("Training and writing model to ", model_file_name)
        models  = {port: train_model(train_data, port, feature_cols) for port in PORTS}
        write_pickle(model_file_name, models)
    else: # read previously saved model
        if not os.path.isfile(model_file_name):
            print("Model file not found!", model_file_name)
            exit()
        print("Loading model from ", model_file_name)
        models = read_pickle(model_file_name)
    return models


def get_model_per_port(model_file_name, train_data, feature_cols):
    if not USE_SAVED_MODEL: # train and save model for later use
        print("Training and writing model to ", model_file_name)
        models  = {port: train_model(train_data, port, feature_cols[port]) for port in PORTS}
        write_pickle(model_file_name, models)
    else: # read previously saved model
        if not os.path.isfile(model_file_name):
            print("Model file not found!", model_file_name)
            exit()
        print("Loading model from ", model_file_name)
        models = read_pickle(model_file_name)
    return models


# ------------
