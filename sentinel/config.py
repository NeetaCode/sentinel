import os


def data_dir(): return os.getenv("SENTINEL_DATA_DIR", "data")
def csv_path(): return os.path.join(data_dir(), "auth.csv")
def labels_path(): return os.path.join(data_dir(), "labels.json")
def model_path(): return os.path.join(data_dir(), "model.joblib")
def db_path(): return os.path.join(data_dir(), "sentinel.db")
def actions_dir(): return os.path.join(data_dir(), "actions")
