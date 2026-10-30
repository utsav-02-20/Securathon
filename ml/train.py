import os
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from typing import Tuple
from core.logger import setup_logger
from data.generate_dataset import DATASET_PATH, generate_and_save_dataset

logger = setup_logger("ml.train")

MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
MODEL_PATH = os.path.join(MODEL_DIR, "isolation_forest.joblib")

FEATURE_COLUMNS = [
    "request_velocity",
    "sequentiality",
    "id_jump_delta",
    "payload_entropy",
    "unique_id_ratio"
]


def load_dataset(csv_path: str = DATASET_PATH) -> Tuple[np.ndarray, np.ndarray, pd.DataFrame]:
    """
    Loads behavioral telemetry dataset from persistent CSV file.
    """
    if not os.path.exists(csv_path):
        logger.info(f"Dataset not found at {csv_path}. Generating dataset...")
        generate_and_save_dataset(csv_path)

    df = pd.read_csv(csv_path)
    X = df[FEATURE_COLUMNS].values
    y = df["label"].values
    return X, y, df


def train_and_save_model(csv_path: str = DATASET_PATH) -> IsolationForest:
    """
    Trains the Isolation Forest novelty detector on the normal baseline inliers.
    Serializes the trained model to disk.
    """
    os.makedirs(MODEL_DIR, exist_ok=True)
    X, y, df = load_dataset(csv_path)

    # Train on normal baseline traffic (One-Class Novelty Detection)
    X_train = X[y == 0]

    logger.info(f"Training IsolationForest on {X_train.shape[0]} normal baseline feature vectors...")
    model = IsolationForest(
        n_estimators=100,
        contamination=0.10,
        max_samples="auto",
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train)

    joblib.dump(model, MODEL_PATH)
    logger.info(f"Isolation Forest model saved successfully to: {MODEL_PATH}")
    return model


def get_trained_model() -> IsolationForest:
    """Loads or trains model."""
    if os.path.exists(MODEL_PATH):
        try:
            return joblib.load(MODEL_PATH)
        except Exception as e:
            logger.warning(f"Error loading model ({e}). Re-training...")
            return train_and_save_model()
    else:
        return train_and_save_model()


if __name__ == "__main__":
    train_and_save_model()
