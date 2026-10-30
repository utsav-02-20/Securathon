import time
import json
from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional
import numpy as np
from core.config import settings
from core.logger import setup_logger
from core.redis_client import get_redis_client
from ml.features import (
    TelemetryFeatures,
    extract_resource_identifier,
    compute_features_from_history
)
from ml.train import get_trained_model

logger = setup_logger("ml.detector")


@dataclass
class AnomalyDetectionResult:
    risk_score: float                # Normalized anomaly risk: 0.0 (safe) to 1.0 (malicious)
    is_anomaly: bool                # True if risk_score >= settings.anomaly_score_threshold
    threshold: float                # Configured anomaly threshold (e.g. 0.75)
    features: Dict[str, float]      # Feature breakdown
    threat_indicators: List[str]    # Human-readable threat flags for SOC analysts
    inference_latency_ms: float     # Sub-millisecond latency tracking


class BehavioralAnomalyDetector:
    """
    Step 4: AI Detective Engine.
    Evaluates behavioral telemetry in real-time using Isolation Forest and sequence analysis.
    Executes in <1ms to preserve strict API gateway SLA latency budgets.
    """

    def __init__(self):
        self.model = get_trained_model()
        self.threshold = settings.anomaly_score_threshold
        self.max_history_length = 10
        self.history_ttl_seconds = 120

    async def evaluate_request(
        self,
        user_id: str,
        path: str,
        query_string: str = "",
        body_text: str = ""
    ) -> AnomalyDetectionResult:
        """
        Extracts telemetry, evaluates the Isolation Forest model,
        and returns the calibrated anomaly risk score.
        """
        t0 = time.perf_counter()
        now = time.time()
        redis_client = await get_redis_client()
        history_key = f"telemetry:history:{user_id}"

        # 1. Fetch Rolling Request History from Redis
        raw_history = await redis_client.get(history_key)
        history_data: List[Dict[str, Any]] = []
        if raw_history:
            try:
                decoded = raw_history.decode("utf-8") if isinstance(raw_history, bytes) else raw_history
                history_data = json.loads(decoded)
            except Exception as e:
                logger.warning(f"Failed to parse rolling telemetry history: {e}")
                history_data = []

        history_timestamps = [item["t"] for item in history_data]
        history_ids = [item.get("id") for item in history_data if item.get("id")]

        # 2. Extract Current Request Identifiers & Features
        current_id = extract_resource_identifier(path)
        features: TelemetryFeatures = compute_features_from_history(
            current_time=now,
            current_id=current_id,
            path=path,
            query_string=query_string,
            body_text=body_text,
            history_timestamps=history_timestamps,
            history_ids=history_ids
        )

        # 3. Update Rolling History in Redis
        updated_history = history_data[-(self.max_history_length - 1):] + [{
            "t": now,
            "id": current_id,
            "path": path
        }]
        try:
            await redis_client.set(
                history_key,
                json.dumps(updated_history),
                ex=self.history_ttl_seconds
            )
        except Exception as e:
            logger.warning(f"Error persisting rolling telemetry to Redis: {e}")

        # 4. Isolation Forest Model Inference
        # Input order matches FEATURE_COLUMNS: [velocity, sequentiality, delta, entropy, unique_ratio]
        feature_vector = np.array([features.to_array()])
        raw_score = float(self.model.decision_function(feature_vector)[0])

        # Normalize score: in IsolationForest trained on inliers, inliers score > 0.05,
        # outliers score < 0.0 (typically -0.05 to -0.25).
        # We invert so higher value = higher anomaly risk
        normalized_risk = float(np.clip((0.08 - raw_score) / 0.16, 0.05, 0.99))

        # 5. Threat Indicator Check
        threat_indicators = []
        
        # Check for sequential ID enumeration
        if features.sequentiality > 0.5 and len(history_ids) >= 2:
            threat_indicators.append("SEQUENTIAL_ID_ENUMERATION")
            normalized_risk = max(normalized_risk, 0.88)

        if features.unique_id_ratio >= 0.85 and len(history_ids) >= 3:
            threat_indicators.append("HIGH_RESOURCE_TRAVERSAL")
            normalized_risk = max(normalized_risk, 0.82)

        if features.request_velocity > 12.0:
            threat_indicators.append("BURST_VELOCITY")
            normalized_risk = max(normalized_risk, 0.80)

        if features.payload_entropy > 4.5:
            threat_indicators.append("HIGH_PAYLOAD_ENTROPY")
            normalized_risk = max(normalized_risk, 0.85)

        risk_score = round(normalized_risk, 3)
        is_anomaly = risk_score >= self.threshold
        inference_latency_ms = round((time.perf_counter() - t0) * 1000, 3)

        if is_anomaly:
            logger.warning(
                f"ANOMALY DETECTED for user={user_id} | Risk Score: {risk_score} | "
                f"Indicators: {threat_indicators} | Latency: {inference_latency_ms}ms"
            )

        return AnomalyDetectionResult(
            risk_score=risk_score,
            is_anomaly=is_anomaly,
            threshold=self.threshold,
            features=features.to_dict(),
            threat_indicators=threat_indicators,
            inference_latency_ms=inference_latency_ms
        )


# Global singleton detector
anomaly_detector = BehavioralAnomalyDetector()
