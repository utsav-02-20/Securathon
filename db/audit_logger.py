import asyncio
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy import select, func, desc

from core.logger import setup_logger
from db.models import SecurityIncident, BlockedEntity, TelemetryLog
from db.session import get_async_session

logger = setup_logger("db.audit")


class AuditLogger:
    """
    High-throughput non-blocking forensic logger.
    Uses an asynchronous in-memory queue and background worker to ingest
    security incident logs without adding latency to the gateway reverse proxy path.
    """

    def __init__(self):
        self.queue: Optional[asyncio.Queue] = None
        self.running: bool = False
        self._worker: Optional[asyncio.Task] = None

    def start(self):
        """Starts the background audit persistence worker in the current active event loop."""
        if not self.running:
            self.running = True
            self.queue = asyncio.Queue()
            self._worker = asyncio.create_task(self._process_queue())
            logger.info("Forensic Audit Logger background worker started.")

    async def stop(self):
        """Flushes remaining items in queue and stops worker cleanly."""
        self.running = False
        if self._worker:
            if self.queue:
                while not self.queue.empty():
                    try:
                        item = self.queue.get_nowait()
                        await self._persist_item(item)
                        self.queue.task_done()
                    except Exception:
                        break
            self._worker.cancel()
            try:
                await self._worker
            except asyncio.CancelledError:
                pass
            self._worker = None
            self.queue = None
            logger.info("Forensic Audit Logger stopped cleanly.")

    async def _process_queue(self):
        """Background loop reading from queue and persisting to PostgreSQL."""
        while self.running and self.queue:
            try:
                item = await self.queue.get()
                await self._persist_item(item)
                self.queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in audit worker loop: {e}")
                await asyncio.sleep(0.05)

    async def _persist_item(self, item: Dict[str, Any]):
        """Persists a single item to the database."""
        item_type = item.get("type")
        data = item.get("data", {})
        try:
            async with get_async_session() as session:
                if item_type == "incident":
                    incident = SecurityIncident(
                        id=data.get("id") or str(uuid.uuid4()),
                        request_id=data.get("request_id"),
                        user_id=data.get("user_id"),
                        client_ip=data.get("client_ip"),
                        endpoint=data.get("endpoint"),
                        http_method=data.get("http_method"),
                        risk_score=data.get("risk_score", 0.0),
                        threat_type=data.get("threat_type", "UNKNOWN"),
                        threat_indicators=data.get("threat_indicators", []),
                        action_taken=data.get("action_taken", "BLOCKED"),
                        features_snapshot=data.get("features_snapshot", {})
                    )
                    session.add(incident)
                elif item_type == "telemetry":
                    log = TelemetryLog(
                        user_id=data.get("user_id"),
                        endpoint=data.get("endpoint"),
                        risk_score=data.get("risk_score", 0.0),
                        latency_ms=data.get("latency_ms", 0.0),
                        status_code=data.get("status_code", 200)
                    )
                    session.add(log)
                elif item_type == "block":
                    blocked = BlockedEntity(
                        entity_type=data.get("entity_type", "USER"),
                        entity_value=data.get("entity_value"),
                        reason=data.get("reason", "Malicious behavioral anomaly detected")
                    )
                    session.add(blocked)
        except Exception as e:
            logger.error(f"Failed to persist audit item ({item_type}): {e}")

    def log_incident_async(
        self,
        request_id: str,
        user_id: str,
        client_ip: str,
        endpoint: str,
        http_method: str,
        risk_score: float,
        threat_type: str,
        threat_indicators: List[str],
        action_taken: str,
        features_snapshot: Dict[str, float]
    ):
        """
        Non-blocking enqueue for security incident persistence.
        Completes in <0.05ms to preserve gateway latency budgets.
        """
        if self.queue is not None:
            self.queue.put_nowait({
                "type": "incident",
                "data": {
                    "id": str(uuid.uuid4()),
                    "request_id": request_id,
                    "user_id": user_id,
                    "client_ip": client_ip,
                    "endpoint": endpoint,
                    "http_method": http_method,
                    "risk_score": risk_score,
                    "threat_type": threat_type,
                    "threat_indicators": threat_indicators,
                    "action_taken": action_taken,
                    "features_snapshot": features_snapshot
                }
            })

    def log_telemetry_async(
        self,
        user_id: str,
        endpoint: str,
        risk_score: float,
        latency_ms: float,
        status_code: int
    ):
        """Non-blocking enqueue for continuous telemetry persistence."""
        if self.queue is not None:
            self.queue.put_nowait({
                "type": "telemetry",
                "data": {
                    "user_id": user_id,
                    "endpoint": endpoint,
                    "risk_score": risk_score,
                    "latency_ms": latency_ms,
                    "status_code": status_code
                }
            })

    async def get_recent_incidents(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Queries the most recent security incidents for forensic inspection and SOC display."""
        async with get_async_session() as session:
            stmt = select(SecurityIncident).order_by(desc(SecurityIncident.timestamp)).limit(limit)
            result = await session.execute(stmt)
            incidents = result.scalars().all()
            return [inc.to_dict() for inc in incidents]

    async def get_incident_summary(self) -> Dict[str, Any]:
        """Returns aggregate incident counts grouped by threat type."""
        async with get_async_session() as session:
            stmt = select(SecurityIncident.threat_type, func.count(SecurityIncident.id)).group_by(SecurityIncident.threat_type)
            result = await session.execute(stmt)
            breakdown = {threat: count for threat, count in result.all()}
            total_stmt = select(func.count(SecurityIncident.id))
            total_res = await session.execute(total_stmt)
            total = total_res.scalar() or 0
            return {
                "total_incidents": total,
                "by_threat_type": breakdown
            }


# Global singleton audit logger
audit_logger = AuditLogger()
