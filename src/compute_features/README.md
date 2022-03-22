##### Compute Features


**`logs_to_features_multi_days.py`**: Processes a sequence of bro log files in csv format and converts them to usable feature files.
 This is a top-level file that calls functions from `logs_to_features_labeled.py` to generate features, history and intermediary object files. 
 LOG_DIR, LOG_FILES, and OUT_DIR_BASE should be set.

**`merge_wcry_to_test.py`**: Merges different the malicious dataset from malware variants into the test day, and generates new features files for the test day.