import os, sys
import pandas as pd
import argparse

sys.path.insert(0, os.path.abspath("../../"))

from constants import COL_HEADERS_TEST
from common import *

def get_score_at_percentile(f, p):
    data = pd.read_csv(f)
    data = data[data['percentile'] == p] 
    score = data.iloc[0]['score']
    print("data at p: \n", data)
    print("score: ", score)
    return score


# get the scores below a threshold
# then get the windows associated with these scores
def get_windows_below_thresh(f, thresh):
    data = pd.read_csv(f)
    data = data[data['prob density score'] <= thresh]
    print("below thresh: \n", data)
    windows = data['window'].values
    print("windows: ", windows)
    return windows


def computing_labels(merged_file, labeled_file, metrics_file, windows, port): 
    data = pd.read_csv(merged_file)
    data = data[data['port'] == port]
    matches = mismatches = 0
    tp = 0
    tn = 0
    fp = 0
    fn = 0
    tp_list = []
    tn_list = []
    fp_list = []
    fn_list = []

    for index, row in data.iterrows():
        tw = data.at[index, "timewindow"]
        if 'label' in data:
            label = data.at[index, "label"]
        else:
            label = False # happens when comparing against a background file rather than a merged file

        if tw in windows: # our algo is labeling it true
            if label == True:  # ground truth label True
                matches += 1
                tp += 1
                tp_list.append(tw)
            else:             # ground truth label false
                mismatches += 1
                fp += 1
                fp_list.append(tw)
        else:  # our algo is labeling it false
            if label == True:
                mismatches += 1
                fn += 1
                fn_list.append(tw)
            else:
                matches += 1
                tn += 1
                tn_list.append(tw)

    print("matches, mismatches, tp, tn, fp, fn: ", matches, mismatches, tp, tn, fp, fn)
    print("tp_list: ", tp_list)
    print("tn_list: ", tn_list)
    print("fp_list: ", fp_list)
    print("fn_list: ", fn_list)
    
    metrics = dict()
    metrics['tp'] = tp_list
    metrics['tn'] = tn_list
    metrics['fp'] = fp_list
    metrics['fn'] = fn_list
    write_pickle(metrics_file, metrics)
 
    metrics_stats = [[len(metrics['tp']),  len(metrics['tn']), len(metrics['fp']), len(metrics['fn'])]]
    pd.DataFrame(metrics_stats, columns=['tp', 'tn', 'fp', 'fn']).to_csv(metrics_file[:-4] + "_stats.csv", index=False)

    data['label'] = False
    for index, row in data.iterrows():
        if data.at[index, "label"] != False:
            print("Should be false!")
            exit()
        if data.at[index, "timewindow"] in windows:
            data.at[index, "label"] = True

    pd.DataFrame(data, columns=COL_HEADERS_TEST).to_csv(labeled_file, index=False)
    print("New labels saved to file : ", labeled_file)


# --- Main ---
if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("OUTPUT_DIR", help="Location of the input/output dir.")
    parser.add_argument("SCORES_TRAINING_DIR", help="Location of the dir with score percentiles on training data.")
    parser.add_argument("TEST_FILE", help="Location of the merged file for the test day.")
    parser.add_argument("PERCENTILE", help="Percentile threshold in training.")
    parser.add_argument("PORT", help="Port.")
    args = parser.parse_args()
    print(args)

    OUTPUT_DIR = args.OUTPUT_DIR
    SCORES_TRAINING_DIR = args.SCORES_TRAINING_DIR
    TEST_FILE = args.TEST_FILE # this is the test file
    PERCENTILE = float(args.PERCENTILE)
    port = int(args.PORT)

    print("port and percentile for labeling: ", port, PERCENTILE)

    # pscore is the threshold score computed on the training data 
    # (windows with scores smaller than this threshold are considered anomalous)
    PERCENTILES_TRAINING_FILE = os.path.join(SCORES_TRAINING_DIR, "percentiles_training_p{}.csv".format(port))
    pscore = get_score_at_percentile(PERCENTILES_TRAINING_FILE, PERCENTILE)
    
    # anomaly scores of the test data
    test_scores_file = os.path.join(OUTPUT_DIR, "anomaly_scores", "infected_p{}.csv".format(port))
    print("test_scores_file:", test_scores_file)

    # will assign labels 1/0 (malicious/benign) based on anomaly scores 
    # anomaly scores which are below the pscore are labeled as malicious
    LABELS_DIR = os.path.join(OUTPUT_DIR, "assigned_labels", str(port))
    LABELS_FILE = os.path.join(LABELS_DIR, "labels_perc_{}_p{}.csv".format(PERCENTILE, port))
    METRICS_FILE = os.path.join(LABELS_DIR, "metrics_perc_{}_p{}.pkl".format(PERCENTILE, port))
    os.makedirs(LABELS_DIR, exist_ok=True)
    
    windows = get_windows_below_thresh(test_scores_file, pscore)
    computing_labels(TEST_FILE, LABELS_FILE, METRICS_FILE, windows, port)


