'''
Functions for training a RandomForest classifier on given data and computing the feature importance of the set of features used in training
'''

from sklearn.ensemble import RandomForestClassifier

import csv, os, sys
from numpy import *
import pandas as pd

from read_features import *


def get_feature_importance(out_file, columns, clf):

        pd.set_option('display.max_rows', None)
        s = pd.Series(clf.feature_importances_, index=columns)
        feat_importance = s.sort_values(ascending=False)
        feat_importance = feat_importance.round(4)
        feat_importance_str = feat_importance.to_string()
        print('Writing feature importance to file: ', out_file)
        print('Feature importance len:', len(clf.feature_importances_))
        print('Number of trees:', len(clf.estimators_))

        with open(out_file, 'a+') as f:
            f.write(feat_importance_str)

        return feat_importance


def get_feature_importance_for_RF(out_file, columns, train_data, rf_n=100):
        X_train, y_train = train_data

        # clf = RandomForestClassifier(random_state=0, n_jobs=-1, n_estimators=10, class_weight='balanced')
        clf = RandomForestClassifier(random_state=0, n_jobs=-1, n_estimators=rf_n)
        clf.fit(X_train, y_train)

        feat_importance = get_feature_importance(out_file, columns, clf)
        return feat_importance


def run_classifier_from_all_dirs(out_file, rf_n=100, port=22, training_dir=None):

        training_files = os.listdir(training_dir)
        columns = get_feature_names(training_files[0], training_dir)
        print("Columns: ", columns)
        print("\n\nPort: ", port) 

        print('Training files:', training_files)
        train_data = read_features(training_dir, training_files, port)
        feat_importance = get_feature_importance_for_RF(out_file, columns, train_data, rf_n)
        print('Finished running classifier\n')
        return feat_importance

    
def run_classifier_vary_param(port, rf_n=100, training_dir=None, results_dir=None):
        fn = "port" + str(port)
        out_file_name = os.path.join(results_dir, fn  + '.csv')
        print(out_file_name)
        os.makedirs(os.path.dirname(out_file_name), exist_ok=True)
            
        feat_imp = run_classifier_from_all_dirs(out_file=out_file_name,
                                                rf_n=rf_n, port=port,
                                                training_dir=training_dir)


