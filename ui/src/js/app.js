import { initThreatChart, updateThreatChart, threatDistribution } from './charts.js';
import { GatewayStreamClient } from './api.js';

let screenedCount = 0;
let blockedCount = 0;

// Update UTC Clock
function startClock() {
  const clockEl = document.getElementById('clock');
  if (clockEl) {
    setInterval(() => {
      clockEl.innerText = new Date().toUTCString().slice(17, 25) + ' UTC';
    }, 1000);
  }
}

// Update Top KPI counters
function updateKPIs() {
  const screenedEl = document.getElementById('kpi-screened');
  const blockedEl = document.getElementById('kpi-blocked');
  const rateEl = document.getElementById('kpi-rate');

  if (screenedEl) screenedEl.innerText = screenedCount;
  if (blockedEl) blockedEl.innerText = blockedCount;
  if (rateEl) {
    const rate = screenedCount > 0 ? ((blockedCount / screenedCount) * 100).toFixed(1) : '0.0';
    rateEl.innerText = `${rate}%`;
  }

  updateThreatChart();
}

// Render dynamic row into the Intercepted Threat Feed
export function handleIncomingEvent(event) {
  screenedCount++;
  if (event.action === 'BLOCKED') blockedCount++;

  const typeKey = threatDistribution.hasOwnProperty(event.event_type)
    ? event.event_type
    : (event.action === 'BLOCKED' ? 'BOLA_IDOR_ATTACK' : 'BENIGN');
  threatDistribution[typeKey] = (threatDistribution[typeKey] || 0) + 1;

  updateKPIs();

  const tbody = document.getElementById('feed-tbody');
  if (!tbody) return;

  const row = document.createElement('tr');

  const actionPill = event.action === 'BLOCKED'
    ? '<span class="pill pill-blocked">BLOCKED 403</span>'
    : (event.action === 'TARPIT'
      ? '<span class="pill pill-tarpit">TARPIT DELAY</span>'
      : '<span class="pill pill-allow">ALLOW 200</span>');

  const scoreColor = event.risk_score >= 0.75
    ? 'var(--red)'
    : (event.risk_score >= 0.50 ? 'var(--amber)' : 'var(--green)');
  const scoreBarWidth = Math.min(100, Math.round(event.risk_score * 100));
  const timeStr = event.timestamp ? event.timestamp.slice(11, 19) : new Date().toISOString().slice(11, 19);

  row.innerHTML = `
    <td style="color: var(--text-muted); font-size: 0.75rem;">${timeStr}</td>
    <td style="font-weight: 600; color: ${event.action === 'BLOCKED' ? 'var(--red)' : 'var(--text)'};">${event.event_type}</td>
    <td><code>${event.user_id || 'anonymous'}</code></td>
    <td><code>${event.endpoint || '/api'}</code></td>
    <td>
      <span style="font-weight: 700; color: ${scoreColor};">${(event.risk_score || 0).toFixed(2)}</span>
      <div class="risk-bar-container">
        <div class="risk-bar-fill" style="width: ${scoreBarWidth}%; background: ${scoreColor};"></div>
      </div>
    </td>
    <td>${actionPill}</td>
  `;

  tbody.insertBefore(row, tbody.firstChild);

  // Maintain max 50 rows in DOM
  if (tbody.children.length > 50) {
    tbody.removeChild(tbody.lastChild);
  }
}

// Clear feed button handler
window.clearFeed = function () {
  const tbody = document.getElementById('feed-tbody');
  if (tbody) tbody.innerHTML = '';
};

// Initialize Application
document.addEventListener('DOMContentLoaded', () => {
  startClock();
  initThreatChart('threatChart');

  const statusText = document.getElementById('ws-status');
  const statusPulse = document.getElementById('ws-pulse');

  const client = new GatewayStreamClient(
    (event) => handleIncomingEvent(event),
    ({ status, color }) => {
      if (statusText) {
        statusText.innerText = status;
        statusText.style.color = color;
      }
      if (statusPulse) {
        statusPulse.style.background = color;
        statusPulse.style.boxShadow = `0 0 8px ${color}`;
      }
    }
  );

  client.connect();
});
