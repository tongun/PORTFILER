'''
In this script, a model is trained on multi class data for predicting which windows of network traffic include
 malicious traffic. This will output raw accuracy numbers, auc numbers, and graphs.
 Standard multi-feature models like KDE and Isolation Forest are used.
'''

# --- Imports ---
import pandas as pd
import numpy as np
import os, sys
import time
from sklearn.metrics import precision_score, recall_score, precision_recall_curve, roc_curve

# add the parent directory to the path
sys.path.insert(0, os.path.abspath("../"))

from common import *
from constants import *
from constants_model import *
from model import *
from plotting import Plotting
# ---------------

# --- Main ---
if __name__ == '__main__':

    plotting = Plotting()

    print("\nFeature cols:", FEATURE_COLS)

    # either read or save the model for faster testing
    os.makedirs(MODEL_DIR, exist_ok=True)
    model_file_name = os.path.join(MODEL_DIR, "{}features_{}_model_{}.obj".format(len(FEATURE_COLS), TRAIN_DAYS, MODEL))
    models = get_model_per_port(model_file_name, train_data=None, feature_cols=FEATURE_COLS)

    print("Test dir: ", TEST_DIR)

    prec_rec = dict()
    roc_results = dict()
    auc_results = dict()
    num_threads = None

    wc_str = TEST_FILE[:-4]

    # dictionary of roc results
    roc_results = dict()
    prec_rec = dict()

    for port in PORTS:
        scaler, model = models[port]
        test_data = pd.read_csv(os.path.join(TEST_DIR, TEST_FILE))
        test_data = test_data[test_data['port'] == port]
        Y = test_data['label'].values

        # compute kde scores for the feature columns of interest
        X = test_data.filter(FEATURE_COLS).values
        print(X)

        print("Testing: port,  min, max, mean, std: ", port, X.min(), X.max(), X.mean(), X.std())
            
        X = scaler.transform(X)
        print("after scaler min, max:", X.min(), X.max())
        print("Testing scaled: port,  min, max, mean, std: ", port, X.min(), X.max(), X.mean(), X.std())

        if MODEL == "multi_bw":   # older model
            scores = model.pdf(X)
        elif MODEL == "isolation":
            scores = model.score_samples(X)
        else:  # KDE model, generally gives best performance
            scores = np.exp(model.score_samples(X))
      
        print("Scores: ", scores)
        roc_results[port] = roc_curve(Y, (-1) * scores)
        prec_rec[port] = precision_recall_curve(Y, (-1) * scores)

    for port in roc_results:
        fpr = roc_results[port][0]
        tpr = roc_results[port][1]
        plotting.plot_roc(fpr, tpr, port)

    title = "ROC curve {}".format(wc_str)
    out_file = os.path.join(OUTPUT_DIR, "roc", wc_str, "roc_{}_ts{}.png".format(wc_str, int(time.time())))
    os.makedirs(os.path.dirname(out_file), exist_ok=True)
    plotting.setup_plot(title)
    plotting.save_and_clear_plot(out_file)
    print("Finished printing .png", out_file)

    for port in prec_rec:
        prec = prec_rec[port][0]
        rec = prec_rec[port][1]
        plotting.plot_prec_recall(rec, prec, port)

    title_pr = "Precision Recall curve {}".format(wc_str)
    out_file_pr = os.path.join(OUTPUT_DIR, "pr", wc_str, "pr_{}_ts{}.png".format(wc_str, int(time.time())))
    os.makedirs(os.path.dirname(out_file_pr), exist_ok=True)
    plotting.setup_plot(title_pr, xlabel="Recall", ylabel="Precision")
    plotting.save_and_clear_plot(out_file_pr)
    print("Finished printing .png", out_file_pr)

# ------------

