#!/bin/sh

SRC_DIR=$(pwd)"/"
DATA_DIR=$SRC_DIR"../data/"

MODEL_DIR=$DATA_DIR"models/kde/"

SCORES_TRAINING_DIR=$DATA_DIR"results/scores_training/mean_ensemble/"
FEATURE_IMPORTANCE_DIR="None"

TEST_FILE=$DATA_DIR"background/feature_extraction/merged_conn_prepared_wannacry/Test_Data_conn_prepared_2011-08-14.csv" 

PORT_INFECTED="22"

# PERCENTILES is a tunable parameter. If it is set too high, we'll get too many false positives; too low will not detect anomalies
# it should be varied to find out the best fit
# PERCENTILES="1 5 10"
PERCENTILES="10"  # threshold on scores from training, below which time windows are considered anomalous 

# the "WEIGHTED" parameter is set to False for mean ensemble method and True for the weighted ensemble
WEIGHTED=False

OUTPUT_DIR=$DATA_DIR"results/ensemble_models/mean_ensemble_detection/"

cd $SRC_DIR"ranking/"

python3 -u compute_scores.py $WEIGHTED $PORT_INFECTED $TEST_FILE $MODEL_DIR $FEATURE_IMPORTANCE_DIR $OUTPUT_DIR
echo "Finshed computing anomaly scores for each test window."

python3 -u ranking_per_port.py $PORT_INFECTED $OUTPUT_DIR
echo "Finished ranking test windows, created performance metrics for verification."

for perc in $PERCENTILES; 
do
    python3 -u label_top_ranked.py $OUTPUT_DIR $SCORES_TRAINING_DIR $TEST_FILE $perc $PORT_INFECTED
done
echo "Finished labeling test windows."


