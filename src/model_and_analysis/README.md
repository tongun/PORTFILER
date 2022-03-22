##### Model and Analysis



**`constants_model.py`**: Contains the configuations variables for model training and evaluation.

# Training

**`train_model.py`**: Trains the model using the training dataset. These can be either standard multi-feature KDE or Isolation Forest models, or single-feature models (KDE/Isolation Forest) that are combined to form ensembles. Parameters need to be set in `constants_model.py`. 

# Standard multi-feature models

**`evaluate_model_per_port.py`**: Evaluates the standard multi-feature models KDE or Isolation Forest on the test dataset, and generates PR&ROC curves.

Sample results can be found in `data/results/standard_models`".

# Ensemble models

**`ensemble/ensemble_for_ranking.py`**: It assignes an aggregate score to each test record (i.e., 1-minute windows) based on the following methodology: 1) Loop through all the features, using a single feature at a time and apply the trained model corresponding to that feature to compute the score of each test record; 2) combine the single-feature scores into a single final score for each test record. 

Possible methods of combining the scores are: 
- Mean Ensemble: taking the mean over all single-feature scores,
- Weighted Ensemble: each single-feature score has a weight, proportional to its feature importance. Feature importance is computed beforehand in a supervised fashion on another labeled attack trace if available, or is based on SOC experience.

# Detection using ensemble models

## Threshold score for labeling

This threshold is figured out from the TRAINING data. It is based on a tunable parameter called percentile (p), which is set to a small value. A percent p of windows from the training  data are considered anomalous. 
Let s be the score that corresponds to percentile p in the training data. E.g., if p=10, it means that 10% of scores in training are <= than s. 
Score s will be considered the threshold below which TEST windows are labeled malicious. 
Percentile p is a tunable parameter and its value affects the accuracy of the detection. If it is set too high, we may end up with many false positives; if it set too low, we may end up with many false negatives.  

**`score_percentiles_in_training`**: It uses the ensemble model to get the score of each 1-minute window from the TRAINING data. After ordering the scores, it finds out what score s is at a specific percentile p. 

## Ranking and labeling test records (i.e., 1-minute windows)

**`ranking/compute_scores.py`**: Computes anomaly scores for each test window. 

**`ranking/ranking_per_port.py`**: Sorts the anomaly scores and computes some performance metrics based on ground truth.

**`ranking/ranking.py`**: auxiliary functions.

**`ranking/label_top_ranked.py`**: Labels the test windows based on parameter p described above in "Threshold score for labeling".

**`run_detection.sh`**: Script for running detection of malicious windows on our sample test data; separate scripts for mean ensemble and weighted ensemble, as examples.

Weighted ensembles use feature importance  coefficients from "data/results/featurre_importance_coefficients". See the Readme in the directory "../feature_importance" for a description of how these coefficients are calculated and used. 
  
Sample detection results using the ensemble methods can be found in: "`data/results/ensemble_models/`". 

