// ZITDA SentinelFlow Dashboard Chart Visualizations
import Chart from 'chart.js/auto';

// Global references to destroy charts on re-load
let protocolChartInstance = null;
let mdaChartInstance = null;
let timelineChartInstance = null;
let threatChartInstance = null;

/**
 * Aggregates packet statistics and renders/updates dashboard charts.
 * @param {Array[]} packets 
 * @param {Array[]} alerts
 */
export function updateCharts(packets, alerts = []) {
  if (!packets || packets.length === 0) return;
  
  // Destroy existing charts to prevent hover bugs
  if (protocolChartInstance) protocolChartInstance.destroy();
  if (mdaChartInstance) mdaChartInstance.destroy();
  if (timelineChartInstance) timelineChartInstance.destroy();
  if (threatChartInstance) threatChartInstance.destroy();
  
  // ----------------------------------------------------
  // 1. Protocol Aggregation
  // ----------------------------------------------------
  const protoCounts = {};
  packets.forEach(p => {
    const proto = p.protocol;
    protoCounts[proto] = (protoCounts[proto] || 0) + 1;
  });
  
  const protoLabels = Object.keys(protoCounts);
  const protoData = Object.values(protoCounts);
  
  // Custom colors matching the ZITDA cybersecurity brand palette
  const protoColors = {
    'cPanel': '#10b981', // ZITDA Green
    'WHM': '#fbbf24',    // Gold
    'Webmail': '#f59e0b',// Amber
    'HTTP': '#06b6d4',   // Cyan
    'TCP': '#3b82f6',    // Blue
    'UDP': '#6366f1',    // Indigo
    'DNS': '#a855f7',    // Purple
    'SMTP': '#ef4444',   // Red
    'FTP': '#ec4899',    // Pink
    'ARP': '#9ca3af',    // Grey
    'ICMP': '#f43f5e'    // Rose
  };
  
  const bgColors = protoLabels.map(label => protoColors[label] || '#6b7280');
  
  // Render Protocol Chart
  const ctxProto = document.getElementById('protocol-chart').getContext('2d');
  protocolChartInstance = new Chart(ctxProto, {
    type: 'doughnut',
    data: {
      labels: protoLabels,
      datasets: [{
        data: protoData,
        backgroundColor: bgColors,
        borderWidth: 1,
        borderColor: 'rgba(255, 255, 255, 0.08)'
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'right',
          labels: {
            color: '#9ca3af',
            font: { family: 'Outfit', size: 11 }
          }
        }
      },
      cutout: '65%'
    }
  });

  // ----------------------------------------------------
  // 2. MDA Traffic Aggregation (Bytes consumed)
  // ----------------------------------------------------
  const mdaDataMap = {
    'zamfara.gov.ng': 0,
    'finance.zm.gov.ng': 0,
    'judiciary.zm.gov.ng': 0,
    'health.zm.gov.ng': 0,
    'revenue.zm.gov.ng': 0
  };
  
  packets.forEach(p => {
    // Attribute bytes to MDA subdomains based on IP addresses
    const checkAndAdd = (ip, size) => {
      if (ip === '192.168.10.10') mdaDataMap['zamfara.gov.ng'] += size;
      else if (ip === '192.168.10.50') mdaDataMap['finance.zm.gov.ng'] += size;
      else if (ip === '192.168.10.60') mdaDataMap['judiciary.zm.gov.ng'] += size;
      else if (ip === '192.168.10.70') mdaDataMap['health.zm.gov.ng'] += size;
      else if (ip === '192.168.10.80') mdaDataMap['revenue.zm.gov.ng'] += size;
    };
    
    checkAndAdd(p.srcIp, p.length);
    checkAndAdd(p.dstIp, p.length);
  });
  
  const mdaLabels = Object.keys(mdaDataMap).map(k => k.split('.')[0].toUpperCase()); // e.g. FINANCE
  const mdaBytes = Object.values(mdaDataMap);
  
  // Render MDA Traffic Chart
  const ctxMda = document.getElementById('mda-chart').getContext('2d');
  const mdaGradient = ctxMda.createLinearGradient(0, 0, 0, 260);
  mdaGradient.addColorStop(0, 'rgba(16, 185, 129, 0.6)');
  mdaGradient.addColorStop(1, 'rgba(16, 185, 129, 0.05)');
  
  mdaChartInstance = new Chart(ctxMda, {
    type: 'bar',
    data: {
      labels: mdaLabels,
      datasets: [{
        label: 'Traffic Volume (Bytes)',
        data: mdaBytes,
        backgroundColor: mdaGradient,
        borderColor: '#10b981',
        borderWidth: 1.5,
        borderRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: {
          ticks: { color: '#9ca3af', font: { family: 'Outfit' } },
          grid: { color: 'rgba(255, 255, 255, 0.05)' }
        },
        y: {
          ticks: { 
            color: '#9ca3af', 
            font: { family: 'Outfit' },
            callback: function(val) {
              if (val >= 1000) return (val / 1000) + ' KB';
              return val + ' B';
            }
          },
          grid: { color: 'rgba(255, 255, 255, 0.05)' }
        }
      },
      plugins: {
        legend: { display: false }
      }
    }
  });

  // ----------------------------------------------------
  // 3. Time Series Timeline Aggregation (Packets over time)
  // ----------------------------------------------------
  // Split time window of capture into 15 logical bins
  const minTime = packets[0].timestampRaw;
  const maxTime = packets[packets.length - 1].timestampRaw;
  const delta = (maxTime - minTime) || 1;
  const numBins = 15;
  const binSize = delta / numBins;
  
  const timeBins = Array(numBins).fill(0);
  const timeLabels = Array(numBins).fill('');
  
  packets.forEach(p => {
    const index = Math.min(Math.floor((p.timestampRaw - minTime) / binSize), numBins - 1);
    timeBins[index]++;
  });
  
  // Generate human-readable time labels for bins
  for (let i = 0; i < numBins; i++) {
    const binTimeSec = minTime + (i * binSize);
    const date = new Date(binTimeSec * 1000);
    timeLabels[i] = date.toISOString().split('T')[1].substring(0, 8); // e.g. 14:02:45
  }
  
  // Render Timeline Chart
  const ctxTimeline = document.getElementById('timeline-chart').getContext('2d');
  const lineGradient = ctxTimeline.createLinearGradient(0, 0, 0, 260);
  lineGradient.addColorStop(0, 'rgba(6, 182, 212, 0.35)');
  lineGradient.addColorStop(1, 'rgba(6, 182, 212, 0)');

  timelineChartInstance = new Chart(ctxTimeline, {
    type: 'line',
    data: {
      labels: timeLabels,
      datasets: [{
        label: 'Packets Rate',
        data: timeBins,
        fill: true,
        backgroundColor: lineGradient,
        borderColor: '#06b6d4',
        borderWidth: 2,
        tension: 0.35,
        pointBackgroundColor: '#06b6d4',
        pointRadius: 3
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: {
          ticks: { color: '#9ca3af', font: { family: 'Outfit', size: 10 } },
          grid: { color: 'rgba(255, 255, 255, 0.03)' }
        },
        y: {
          ticks: { color: '#9ca3af', font: { family: 'Outfit' } },
          grid: { color: 'rgba(255, 255, 255, 0.05)' }
        }
      },
      plugins: {
        legend: { display: false }
      }
    }
  });

  // ----------------------------------------------------
  // 4. Security Threat Category Distribution (Polar Area)
  // ----------------------------------------------------
  const threatCounts = {};
  alerts.forEach(a => {
    const cat = a.category || 'Policy Violation';
    threatCounts[cat] = (threatCounts[cat] || 0) + 1;
  });
  
  const threatLabels = Object.keys(threatCounts);
  const threatData = Object.values(threatCounts);
  
  const threatColors = {
    'Application Attack': '#ef4444',     // Crimson
    'Reconnaissance': '#fbbf24',         // Gold
    'Credential Cracking': '#ec4899',    // Pink
    'Identity Exposure': '#8b5cf6',      // Purple
    'Denial of Service': '#3b82f6',       // Blue
    'Policy Violation': '#06b6d4',       // Cyan
    'Hijacked Account': '#f43f5e'        // Rose
  };
  
  const threatBgColors = threatLabels.map(lbl => threatColors[lbl] || '#6b7280');
  
  const ctxThreat = document.getElementById('threat-chart').getContext('2d');
  threatChartInstance = new Chart(ctxThreat, {
    type: 'polarArea',
    data: {
      labels: threatLabels,
      datasets: [{
        data: threatData,
        backgroundColor: threatBgColors.map(color => color + 'b3'), // 70% opacity
        borderColor: 'rgba(255, 255, 255, 0.12)',
        borderWidth: 1.5
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        r: {
          grid: { color: 'rgba(255, 255, 255, 0.05)' },
          angleLines: { color: 'rgba(255, 255, 255, 0.05)' },
          pointLabels: {
            color: '#9ca3af',
            font: { family: 'Outfit', size: 9 }
          },
          ticks: {
            color: '#9ca3af',
            backdropColor: 'transparent',
            stepSize: 1
          }
        }
      },
      plugins: {
        legend: {
          position: 'right',
          labels: {
            color: '#9ca3af',
            font: { family: 'Outfit', size: 9.5 }
          }
        }
      }
    }
  });
}
