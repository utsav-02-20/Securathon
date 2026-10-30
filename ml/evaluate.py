import os
import time
import json
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, precision_score, recall_score, f1_score, roc_auc_score
from core.logger import setup_logger
from ml.train import MODEL_PATH, FEATURE_COLUMNS, get_trained_model, load_dataset
from data.generate_dataset import DATASET_PATH

logger = setup_logger("ml.evaluate")

REPORT_PATH = os.path.join(os.path.dirname(__file__), "metrics_report.json")


def evaluate_model(csv_path: str = DATASET_PATH) -> dict:
    """
    Evaluates the trained Isolation Forest model on the persistent telemetry dataset.
    Calculates precision, recall, F1-score, BOLA-specific detection rate, ROC-AUC,
    and benchmarks sub-millisecond inference latency across 1,000 iterations.
    """
    logger.info(f"Loading evaluation dataset from {csv_path}...")
    X, y_true, df = load_dataset(csv_path)

    logger.info("Loading serialized IsolationForest model...")
    model = get_trained_model()

    # Raw anomaly scores: in IsolationForest, lower decision_function = more anomalous
    raw_scores = model.decision_function(X)
    
    # Invert scores so higher = more anomalous
    anomaly_scores = -raw_scores

    # Calibrate threshold at the 92nd percentile of normal baseline
    normal_scores = anomaly_scores[y_true == 0]
    threshold = float(np.percentile(normal_scores, 92))
    
    # Binary predictions based on calibrated threshold
    y_pred = np.where(anomaly_scores > threshold, 1, 0)

    # Calculate overall metrics
    precision = float(precision_score(y_true, y_pred, zero_division=0))
    recall = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    auc = float(roc_auc_score(y_true, anomaly_scores))
    cm = confusion_matrix(y_true, y_pred).tolist()

    # BOLA / IDOR specific detection rate
    bola_mask = df["attack_type"] == "BOLA_SEQUENTIAL_IDOR"
    bola_total = int(np.sum(bola_mask))
    bola_caught = int(np.sum(y_pred[bola_mask] == 1))
    bola_detection_rate = float(round(bola_caught / max(1, bola_total), 4))

    # Parameter fuzzing detection rate
    fuzz_mask = df["attack_type"] == "PARAM_FUZZING_HIGH_ENTROPY"
    fuzz_total = int(np.sum(fuzz_mask))
    fuzz_caught = int(np.sum(y_pred[fuzz_mask] == 1))
    fuzz_detection_rate = float(round(fuzz_caught / max(1, fuzz_total), 4))

    # Benchmark sub-millisecond inference latency over 1,000 iterations
    latencies = []
    test_sample = X[0:1]
    for _ in range(1000):
        t0 = time.perf_counter()
        _ = model.decision_function(test_sample)
        latencies.append((time.perf_counter() - t0) * 1000)

    avg_latency_ms = float(round(np.mean(latencies), 4))
    p95_latency_ms = float(round(np.percentile(latencies, 95), 4))
    p99_latency_ms = float(round(np.percentile(latencies, 99), 4))

    report = {
        "dataset_samples": len(df),
        "total_anomalies": int(np.sum(y_true == 1)),
        "total_normal": int(np.sum(y_true == 0)),
        "roc_auc_score": round(auc, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "calibrated_threshold": round(threshold, 4),
        "confusion_matrix": {
            "true_negatives": cm[0][0],
            "false_positives": cm[0][1],
            "false_negatives": cm[1][0],
            "true_positives": cm[1][1]
        },
        "attack_breakdown": {
            "bola_idor_detection_rate": bola_detection_rate,
            "bola_samples_tested": bola_total,
            "bola_detected": bola_caught,
            "fuzzing_detection_rate": fuzz_detection_rate,
            "fuzzing_samples_tested": fuzz_total,
            "fuzzing_detected": fuzz_caught
        },
        "latency_benchmark": {
            "avg_latency_ms": avg_latency_ms,
            "p95_latency_ms": p95_latency_ms,
            "p99_latency_ms": p99_latency_ms,
            "sla_target_ms": 15.0,
            "sla_met": bool(p99_latency_ms < 15.0)
        }
    }

    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    logger.info("=" * 60)
    logger.info("AI DETECTIVE MODEL EVALUATION REPORT")
    logger.info("=" * 60)
    logger.info(f"ROC-AUC: {report['roc_auc_score']:.4f} | Precision: {report['precision'] * 100:.2f}% | Recall: {report['recall'] * 100:.2f}% | F1: {report['f1_score']:.4f}")
    logger.info(f"BOLA / IDOR Detection Rate: {bola_detection_rate * 100:.2f}% ({bola_caught}/{bola_total} attacks caught)")
    logger.info(f"Parameter Fuzzing Detection Rate: {fuzz_detection_rate * 100:.2f}% ({fuzz_caught}/{fuzz_total} caught)")
    logger.info(f"Average Inference Latency: {avg_latency_ms:.4f}ms (P99: {p99_latency_ms:.4f}ms | SLA Target: <15ms)")
    logger.info(f"Metrics report saved to: {REPORT_PATH}")
    logger.info("=" * 60)

    return report


if __name__ == "__main__":
    evaluate_model()
