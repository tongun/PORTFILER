'''
Runs the RandomForest classifier for supervised learning, with the goal of ranking features on each port based on their importance.
'''

import argparse
from datetime import datetime
from classifier import *

if __name__ == "__main__":

    RESULTS_DIR = os.path.join("../data/results", "feature_importance_coefficients/")

    # feature importance is computed on a separate set of labeled data, which is not used in training or testing for PORTFILER
    # here, we give an example on the sample file from 2011-08-12
    # the random forest classifier is trained on this labeled data to get the feature importance coefficients
    DIR_FOR_COMPUTING_FEATURE_IMP = "../data/background/data_for_getting_feature_importance/train_RF/"

    # Random Forest parameters
    rf_n = 100  # n_estimators
    ports = [22, 23, 80, 443, 445]
    # ports = [22]

    for port in ports:
        run_classifier_vary_param(port, rf_n=rf_n, 
                training_dir=DIR_FOR_COMPUTING_FEATURE_IMP, results_dir=RESULTS_DIR)


