/**
 * Securathon SOC Dashboard - Chart Controller
 */

export const threatDistribution = {
  "BOLA_IDOR_ATTACK": 0,
  "RATE_LIMIT_DROP": 0,
  "ALG_NONE_EXPLOIT": 0,
  "PARAM_FUZZING_ATTACK": 0,
  "TOKEN_EXPIRED": 0,
  "MISSING_TOKEN": 0,
  "BURST_SCRAPER_ATTACK": 0,
  "BENIGN": 0
};

let threatChartInstance = null;

export function initThreatChart(canvasId) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return null;

  const ctx = canvas.getContext('2d');
  threatChartInstance = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['BOLA / IDOR', 'Rate Limit', 'alg: none', 'Fuzzing / SQLi', 'Auth Replay', 'Normal Traffic'],
      datasets: [{
        data: [0, 0, 0, 0, 0, 0],
        backgroundColor: [
          '#ff3366', // BOLA - red
          '#f59e0b', // Rate limit - amber
          '#8b5cf6', // alg: none - purple
          '#ec4899', // Fuzzing - pink
          '#3b82f6', // Auth - blue
          '#10b981'  // Benign - green
        ],
        borderWidth: 0
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'bottom',
          labels: {
            color: '#94a3b8',
            font: { size: 10 },
            boxWidth: 12
          }
        }
      }
    }
  });

  return threatChartInstance;
}

export function updateThreatChart() {
  if (!threatChartInstance) return;

  threatChartInstance.data.datasets[0].data = [
    threatDistribution["BOLA_IDOR_ATTACK"],
    threatDistribution["RATE_LIMIT_DROP"],
    threatDistribution["ALG_NONE_EXPLOIT"],
    threatDistribution["PARAM_FUZZING_ATTACK"],
    threatDistribution["TOKEN_EXPIRED"] + threatDistribution["MISSING_TOKEN"],
    threatDistribution["BENIGN"]
  ];
  threatChartInstance.update();
}
