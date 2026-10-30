import re
import math
import time
from collections import Counter
from dataclasses import dataclass
from typing import List, Optional, Tuple, Dict, Any


@dataclass
class TelemetryFeatures:
    request_velocity: float    # Requests per second in rolling window
    id_jump_delta: float       # Absolute difference between current and previous resource ID
    id_jump_variance: float    # Variance of the last N consecutive ID deltas
    sequentiality: float       # 1.0 / (1.0 + id_jump_variance) -> ~1.0 for BOLA, ~0.03 for normal
    payload_entropy: float     # Shannon entropy of path + query + payload
    unique_id_ratio: float     # Ratio of unique resource IDs to total requests in window

    def to_array(self) -> List[float]:
        """Returns ordered feature vector for Isolation Forest inference."""
        return [
            round(self.request_velocity, 4),
            round(self.sequentiality, 4),
            round(self.id_jump_delta, 4),
            round(self.payload_entropy, 4),
            round(self.unique_id_ratio, 4)
        ]

    def to_dict(self) -> Dict[str, float]:
        """Returns feature breakdown dictionary for forensic logging & SOC dashboard."""
        return {
            "request_velocity": round(self.request_velocity, 4),
            "id_jump_delta": round(self.id_jump_delta, 4),
            "id_jump_variance": round(self.id_jump_variance, 4),
            "sequentiality": round(self.sequentiality, 4),
            "payload_entropy": round(self.payload_entropy, 4),
            "unique_id_ratio": round(self.unique_id_ratio, 4)
        }


def calculate_shannon_entropy(data: str) -> float:
    """
    Computes Shannon Entropy H(X) = -SUM(p * log2(p)) for string data.
    Quantifies randomness / entropy:
    - Normal URLs / structured JSON: ~2.0 to 4.2
    - Obfuscated / base64 / fuzzed payloads: > 4.7
    """
    if not data:
        return 0.0
    
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


RESOURCE_ID_REGEX = re.compile(r'/(?:orders|users|transactions|items|accounts|invoices)/([a-zA-Z0-9_\-]+)', re.IGNORECASE)


def extract_resource_identifier(path: str) -> Optional[str]:
    """
    Extracts resource identifiers from standard REST API paths.
    E.g. '/api/v1/orders/1001' -> '1001'
    """
    match = RESOURCE_ID_REGEX.search(path)
    if match:
        return match.group(1)
    
    segments = [s for s in path.strip('/').split('/') if s]
    if segments:
        last = segments[-1]
        if last.isdigit() or (len(last) >= 3 and any(c.isdigit() for c in last)):
            return last
    return None


def calculate_variance(values: List[float]) -> float:
    """Computes variance of a list of floats."""
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    return sum((x - mean) ** 2 for x in values) / len(values)


def compute_features_from_history(
    current_time: float,
    current_id: Optional[str],
    path: str,
    query_string: str,
    body_text: str,
    history_timestamps: List[float],
    history_ids: List[str]
) -> TelemetryFeatures:
    """
    Computes the behavioral telemetry feature vector
    from the current request and the user's rolling Redis history.
    """
    # 1. Request Velocity (requests per second)
    all_timestamps = history_timestamps + [current_time]
    if len(all_timestamps) >= 2:
        time_span = max(0.2, all_timestamps[-1] - all_timestamps[0])
        velocity = len(all_timestamps) / time_span
    else:
        velocity = 0.5  # Baseline normal velocity for isolated request

    # 2. Resource ID jump delta, variance, and sequentiality
    all_ids = history_ids + ([current_id] if current_id else [])
    
    # Calculate unique resource ratio
    if all_ids:
        unique_ratio = len(set(all_ids)) / len(all_ids)
    else:
        unique_ratio = 0.2

    numeric_ids: List[float] = []
    for rid in all_ids:
        try:
            numeric_ids.append(float(rid))
        except (ValueError, TypeError):
            if rid:
                numeric_ids.append(float(abs(hash(rid)) % 10000))

    if len(numeric_ids) >= 2:
        jump_delta = abs(numeric_ids[-1] - numeric_ids[-2])
        deltas = [abs(numeric_ids[i] - numeric_ids[i-1]) for i in range(1, len(numeric_ids))]
        
        # A sequence requires at least 2 transitions (3+ requests) to establish variance
        if len(deltas) >= 2:
            jump_variance = calculate_variance(deltas)
            if jump_delta >= 1.0 and unique_ratio >= 0.6:
                sequentiality = 1.0 / (1.0 + jump_variance)
            else:
                sequentiality = 0.02
        else:
            jump_variance = 25.0
            sequentiality = 0.02
    else:
        jump_delta = 0.0
        jump_variance = 30.0
        sequentiality = 0.02

    # 3. Payload Entropy
    combined_payload = f"{path}?{query_string}#{body_text[:200]}"
    payload_entropy = calculate_shannon_entropy(combined_payload)

    return TelemetryFeatures(
        request_velocity=velocity,
        id_jump_delta=jump_delta,
        id_jump_variance=jump_variance,
        sequentiality=sequentiality,
        payload_entropy=payload_entropy,
        unique_id_ratio=unique_ratio
    )
