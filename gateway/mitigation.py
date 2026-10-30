from dataclasses import dataclass
from typing import List, Dict, Any, Optional
from core.config import settings
from ml.detector import AnomalyDetectionResult
from core.logger import setup_logger

logger = setup_logger("gateway.mitigation")


@dataclass
class MitigationDecision:
    action: str                     # "ALLOW", "BLOCK", "TARPIT"
    risk_score: float               # Calibrated risk score (0.0 to 1.0)
    delay_seconds: float            # Delay to apply if TARPIT
    threat_type: str                # Identified threat category
    threat_indicators: List[str]    # Specific detected telemetry anomalies
    should_revoke_token: bool       # Whether to automatically blacklist token JTI in Redis
    reason: str                     # Human-readable explanation


class MitigationEngine:
    """
    Step 5: Automated Threat Mitigation Pipeline.
    Evaluates AI risk scores and executes enforcement policies:
    - Low Risk (< 0.65) -> ALLOW & Forward to microservice
    - Moderate Risk (0.65 - 0.74) -> TARPIT (latency injection to exhaust bot sockets)
    - High Risk (>= 0.75) -> BLOCK (HTTP 403) & Auto-revoke token in Redis
    """

    def __init__(
        self,
        block_threshold: Optional[float] = None,
        tarpit_threshold: float = 0.65,
        tarpit_delay: Optional[float] = None
    ):
        self.block_threshold = block_threshold or settings.anomaly_score_threshold
        self.tarpit_threshold = tarpit_threshold
        self.tarpit_delay = tarpit_delay or settings.tarpit_delay_seconds

    def decide(self, eval_result: AnomalyDetectionResult) -> MitigationDecision:
        score = eval_result.risk_score
        indicators = eval_result.threat_indicators

        # 1. Hard Block for High-Risk Behavioral Anomalies
        if score >= self.block_threshold:
            if "SEQUENTIAL_ID_ENUMERATION" in indicators:
                threat_type = "BOLA_IDOR_ATTACK"
            elif "HIGH_PAYLOAD_ENTROPY" in indicators:
                threat_type = "PARAM_FUZZING_ATTACK"
            elif "BURST_VELOCITY" in indicators:
                threat_type = "BURST_SCRAPER_ATTACK"
            else:
                threat_type = "BEHAVIORAL_ANOMALY"

            logger.critical(
                f"MITIGATION ACTION [BLOCK]: Threat={threat_type} | Score={score:.3f} | "
                f"Indicators={indicators}"
            )

            return MitigationDecision(
                action="BLOCK",
                risk_score=score,
                delay_seconds=0.0,
                threat_type=threat_type,
                threat_indicators=indicators,
                should_revoke_token=True,
                reason=f"Access denied: High anomaly risk ({score:.2f}) indicates {threat_type}."
            )

        # 2. Tarpit Mode for Moderate Suspicion
        elif score >= self.tarpit_threshold:
            logger.warning(
                f"MITIGATION ACTION [TARPIT]: Score={score:.3f} | Delay={self.tarpit_delay}s"
            )
            return MitigationDecision(
                action="TARPIT",
                risk_score=score,
                delay_seconds=self.tarpit_delay,
                threat_type="ELEVATED_SUSPICION",
                threat_indicators=indicators,
                should_revoke_token=False,
                reason=f"Tarpit delay applied ({self.tarpit_delay}s) due to elevated suspicion."
            )

        # 3. Allow Normal Traffic
        else:
            return MitigationDecision(
                action="ALLOW",
                risk_score=score,
                delay_seconds=0.0,
                threat_type="BENIGN",
                threat_indicators=[],
                should_revoke_token=False,
                reason="Normal behavior within safe risk bounds."
            )


# Global singleton mitigation engine
mitigation_engine = MitigationEngine()

