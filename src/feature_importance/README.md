##### Compute Features Importance Coefficients
  
Feature importance coefficients are used as weights for the Weighted Ensemble method. They are computed by running a Random Forest (RF) classifier on some data other than the one used for training or testing the ensemble.

- You can find sample data in `data/background/data_for_getting_feature_importance` using Aug 12 as background data and `data/wannacry/wannacry/16conn_prepared.log` as malicious data. 
- The merged and labeled result is under `data/background/data_for_getting_feature_importance/train_RF/Test_Data_16conn_prepared_2011-08-12.csv`. 
- A Random Forest classifier is trained on the merged data to get the feature importance coefficients by running: `python3 -u run_classifier.py`
- The feature importance coefficients are saved in: `data/results/feature_importance_coefficients` for each port separately.

Source code files:
- read_features.py: reads the data on which the RF classifier is run.
- classifier.py: runs the RF classifier and calculates feature importance coefficients and saves them to a file. 
- run_classifier.py: top  level file, sets some parameters to run the RF classifier


