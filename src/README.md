## PORTFILER: SPM Detection on Network Traffic

Project goal: Detect anomalous time windows on different port using the Zeek connection traces.

#### Code Structure

##### Prepare Data

* Contains scripts to extract, filter, and convert the JSON formatted zeek logs, and splits across multiple days.

##### Compute Features

* Contains scripts to compute features per day.

##### Model and Analysis

* Train and evaluate models
    * Multi-feature KDE
    * Single-feature KDEs
    * Multi-feature Isolation Forest
    * Single-feature Isolation Forests

#### Pipeline using sample data

Tested on python3.7.

#### Training

1) Extract and create filtered CSV files from the raw logs using `bro_logs_to_csv.py` in prepare_data.
    * Sample conn.log data in: `data/background/conn.log` (see "Sample Data" below)
    * Resulting data: `data/background/2011/08/*/extracted_conn_features`

2) Compute features using `logs_to_features_multi_days.py` in compute_features.
    * This will result in the folder containing feature files: `data/background/feature_extraction/features`

2) Train the model in model_and_analysis:
    * Set parameters in `constants_model.py`, and run `train_model.py`
    * The models will be saved here: `data/models`
    
#### Testing

1) Prepare malicious dataset using `extract_malicious_traffic.py` in prepare_data. 
    * Sample data in: `data/wannacry/wannacry/conn.log` (see "Sample Data" below)
    * Resulting data: `data/wannacry/wannacry/conn_prepared.log`

2) (Optional) Create malicious datasets based on evasive variants of the malware.
    *`create_variants.py` in prepare_data creates more datasets in `data/wannacry/wannacry/`

3) Merge the malicious traffic into the test data.
    * `merge_wcry_to_test.py` merges all variants in the directory `data/wannacry/wannacry/` to create separate test files in `data/background/feature_extraction/merged_conn_prepared_wannacry`
    
3) Run the model on the test data:
    * `evaluate_model_per_port.py` runs the test data on the trained model (using the standard multi-feature models and the same parameters from `constants_model.py`)
    * run ensemble models on the test data in order to rank and label anomalies, as described in "model_and_analysis/Readme.md".

4) The detection results are collected at `data/results/`



#### Sample Data

We could not release the dataset used in our paper. In this codebase, we use public datasets.
  
Dataset files are generated in the Stratosphere Lab as part of the Malware Capture Facility Project in the CVUT University, Prague, Czech Republic.

Stratosphere. (2015). Stratosphere Laboratory Datasets. Retrieved March 13, 2020, from https://www.stratosphereips.org/datasets-overview
##### Background data 

Data description: https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-44/
Log file: https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-44/bro/conn.log

We include only the background data excluding the botnet traffic.

Data directory: `data/background`

##### Malware (WannaCry) data 

Data description: https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-256-1
Log file: https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-256-1/bro/conn.log

Data directory: `data/wannacry`
