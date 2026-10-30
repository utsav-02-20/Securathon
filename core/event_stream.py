import asyncio
import json
import uuid
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import Set, Dict, Any, List, Optional
from fastapi import WebSocket
from core.logger import setup_logger
from core.redis_client import get_redis_client

logger = setup_logger("core.event_stream")

REDIS_THREAT_CHANNEL = "security:threat-stream"


@dataclass
class ThreatEvent:
    event_id: str
    timestamp: str
    event_type: str             # BOLA_ATTACK, RATE_LIMIT_DROP, ALG_NONE_EXPLOIT, TOKEN_REVOKED, REQUEST_ALLOWED
    user_id: str
    client_ip: str
    endpoint: str
    http_method: str
    risk_score: float
    action: str                 # BLOCKED, TARPIT, ALLOW
    threat_indicators: List[str]
    latency_ms: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


class ConnectionManager:
    """
    Manages active WebSocket connections to the SOC Dashboard and broadcasts
    security threat telemetry in real-time.
    Supports dual-dispatch: direct WebSocket broadcast + Redis Pub/Sub.
    """

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self.total_screened: int = 0
        self.total_blocked: int = 0
        self.total_anomalies: int = 0

    async def connect(self, websocket: WebSocket):
        """Registers a new WebSocket client connection."""
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info(f"SOC Dashboard connected. Total active observers: {len(self.active_connections)}")

        # Send initial connection handshake and baseline metrics
        handshake_payload = {
            "type": "HANDSHAKE",
            "message": "Connected to Securathon Live Threat Stream",
            "active_observers": len(self.active_connections),
            "stats": {
                "total_screened": self.total_screened,
                "total_blocked": self.total_blocked,
                "total_anomalies": self.total_anomalies
            }
        }
        await websocket.send_text(json.dumps(handshake_payload))

    def disconnect(self, websocket: WebSocket):
        """Unregisters a disconnected WebSocket client."""
        self.active_connections.discard(websocket)
        logger.info(f"SOC Dashboard disconnected. Remaining active observers: {len(self.active_connections)}")

    async def broadcast(self, event: ThreatEvent):
        """
        Broadcasts threat events in real-time:
        1. Emits immediately to all active dashboard WebSockets (<0.1ms).
        2. Publishes to Redis channel for multi-instance distributed gateways.
        """
        self.total_screened += 1
        if event.action == "BLOCKED":
            self.total_blocked += 1
        if event.risk_score >= 0.75:
            self.total_anomalies += 1

        payload_json = event.to_json()

        # 1. Direct WebSocket broadcast
        disconnected = set()
        for connection in list(self.active_connections):
            try:
                await connection.send_text(payload_json)
            except Exception as e:
                logger.warning(f"Error sending to WebSocket client: {e}")
                disconnected.add(connection)

        for dead_conn in disconnected:
            self.active_connections.discard(dead_conn)

        # 2. Redis Pub/Sub broadcast
        try:
            r = await get_redis_client()
            await r.publish(REDIS_THREAT_CHANNEL, payload_json)
        except Exception as e:
            logger.debug(f"Redis publish skipped or failed: {e}")

    def create_event(
        self,
        event_type: str,
        user_id: str,
        client_ip: str,
        endpoint: str,
        http_method: str,
        risk_score: float,
        action: str,
        threat_indicators: Optional[List[str]] = None,
        latency_ms: float = 0.0
    ) -> ThreatEvent:
        """Helper to construct a standardized ThreatEvent."""
        return ThreatEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=event_type,
            user_id=user_id,
            client_ip=client_ip,
            endpoint=endpoint,
            http_method=http_method,
            risk_score=round(risk_score, 3),
            action=action,
            threat_indicators=threat_indicators or [],
            latency_ms=round(latency_ms, 2)
        )


# Global singleton event broadcaster
event_broadcaster = ConnectionManager()

