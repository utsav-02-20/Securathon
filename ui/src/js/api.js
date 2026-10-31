/**
 * Securathon SOC Dashboard - Real-time Gateway Connector
 */

export class GatewayStreamClient {
  constructor(onEventCallback, onStatusChangeCallback) {
    this.onEvent = onEventCallback;
    this.onStatusChange = onStatusChangeCallback;
    this.ws = null;
    this.reconnectTimer = null;
  }

  connect() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host || '127.0.0.1:8000';
    const wsUrl = `${protocol}//${host}/ws/security-stream`;

    this.onStatusChange({ status: 'CONNECTING', color: 'var(--amber)' });

    try {
      this.ws = new WebSocket(wsUrl);

      this.ws.onopen = () => {
        this.onStatusChange({ status: 'LIVE (CONNECTED)', color: 'var(--green)' });
      };

      this.ws.onmessage = (msg) => {
        try {
          const event = JSON.parse(msg.data);
          if (event.type !== 'HANDSHAKE') {
            this.onEvent(event);
          }
        } catch (err) {
          console.error('[GatewayStreamClient] Failed to parse message:', err);
        }
      };

      this.ws.onclose = () => {
        this.onStatusChange({ status: 'OFFLINE (RECONNECTING...)', color: 'var(--red)' });
        this.scheduleReconnect();
      };

      this.ws.onerror = (err) => {
        console.warn('[GatewayStreamClient] WebSocket error:', err);
        this.ws.close();
      };
    } catch (e) {
      this.onStatusChange({ status: 'ERROR', color: 'var(--red)' });
      this.scheduleReconnect();
    }
  }

  scheduleReconnect() {
    if (this.reconnectTimer) return;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, 3000);
  }
}
