// ZITDA SentinelFlow Main Application Orchestrator
import { parsePcap } from './utils/pcapParser.js';
import { analyzeThreats } from './utils/threatEngine.js';
import { updateCharts } from './utils/dashboard.js';
import { generateDemoPcap } from './utils/demoGenerator.js';
import { compileForensicReport } from './utils/reportGenerator.js';

// Global State
let allPackets = [];
let filteredPackets = [];
let allAlerts = [];
let selectedPacketId = null;

// Pagination settings
let currentPage = 1;
const pageSize = 20;

// ==========================================================
// 1. App Initialization & Tab Routing
// ==========================================================
document.addEventListener('DOMContentLoaded', () => {
  setupLogin();
  setupTabs();
  setupUploader();
  setupSimulation();
  setupTableFilters();
  setupReportAction();
});

function setupLogin() {
  const loginForm = document.getElementById('login-form');
  const loginScreen = document.getElementById('login-screen');
  const appContainer = document.getElementById('main-app-container');
  const loginStatus = document.getElementById('login-status');
  const logoutBtn = document.getElementById('logout-btn');
  const headerRole = document.getElementById('header-user-role');
  const reportInvestigator = document.getElementById('report-investigator');
  
  loginForm.addEventListener('submit', (e) => {
    e.preventDefault();
    
    const usernameInput = document.getElementById('login-username').value.trim();
    const passwordInput = document.getElementById('login-password').value;
    
    let role = "";
    
    // Map specific logins to their authorized roles
    if (usernameInput === 'lead.auditor@zitda.gov.ng' && passwordInput === 'LeadAuditor2026!') {
      role = "Lead Forensics Auditor";
    } else if (usernameInput === 'analyst@zitda.gov.ng' && passwordInput === 'ZitdaAdmin2026!') {
      role = "Security Operations Analyst";
    } else if (usernameInput === 'federal.compliance@nitda.gov.ng' && passwordInput === 'FederalAudit2026!') {
      role = "External Compliance Auditor";
    }
    
    // Enforce ZITDA credentials verification
    if (!role) {
      loginStatus.style.display = 'block';
      loginStatus.style.color = 'var(--zitda-crimson)';
      loginStatus.innerHTML = `❌ Authentication Failed: Invalid Operator Username or Access PIN.`;
      return;
    }
    
    // Show secure crypt audit loading text
    loginStatus.style.display = 'block';
    loginStatus.style.color = 'var(--zitda-gold)';
    loginStatus.innerHTML = `
      <span class="auth-spinner" style="display:inline-block; margin-right: 5px;">⚡</span>
      Decrypting Operator Profile &amp; Syncing Audit Logs...
    `;
    
    setTimeout(() => {
      loginStatus.style.color = 'var(--zitda-green)';
      loginStatus.innerHTML = `✔ Access Authorized. Syncing ZITDA Console...`;
      
      setTimeout(() => {
        // Swap views
        loginScreen.style.display = 'none';
        appContainer.style.display = 'flex';
        
        // Save auditor profile context
        headerRole.textContent = role;
        reportInvestigator.value = `${role}, ZITDA`;
        
        loginStatus.style.display = 'none';
        loginStatus.innerHTML = '';
      }, 550);
    }, 1300);
  });
  
  logoutBtn.addEventListener('click', () => {
    // Clean memory states
    allPackets = [];
    filteredPackets = [];
    allAlerts = [];
    selectedPacketId = null;
    
    // Clear metrics cards
    document.getElementById('metric-total-packets').textContent = '0';
    document.getElementById('metric-total-volume').textContent = '0 Bytes';
    document.getElementById('metric-alerts').textContent = '0';
    document.getElementById('metric-score').textContent = '100%';
    document.getElementById('file-details').style.display = 'none';
    document.getElementById('alert-tab-badge').style.display = 'none';
    
    // Reset file details inputs
    document.getElementById('pcap-file-input').value = '';
    document.getElementById('login-password').value = 'ZitdaAdmin2026!';
    document.getElementById('login-username').value = 'analyst@zitda.gov.ng';
    
    // Return to landing portal
    appContainer.style.display = 'none';
    loginScreen.style.display = 'flex';
  });
}

function setupTabs() {
  const tabs = document.querySelectorAll('.tab-btn');
  const panes = document.querySelectorAll('.tab-pane');
  
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      // Remove active classes
      tabs.forEach(t => t.classList.remove('active'));
      panes.forEach(p => p.classList.remove('active'));
      
      // Add active class to clicked tab and corresponding pane
      tab.classList.add('active');
      const targetPane = document.getElementById(tab.dataset.tab);
      if (targetPane) {
        targetPane.classList.add('active');
      }
    });
  });
}

// ==========================================================
// 2. PCAP Binary File Uploader Setup
// ==========================================================
function setupUploader() {
  const zone = document.getElementById('drag-drop-zone');
  const input = document.getElementById('pcap-file-input');
  
  zone.addEventListener('click', () => input.click());
  
  zone.addEventListener('dragover', (e) => {
    e.preventDefault();
    zone.classList.add('dragover');
  });
  
  zone.addEventListener('dragleave', () => {
    zone.classList.remove('dragover');
  });
  
  zone.addEventListener('drop', (e) => {
    e.preventDefault();
    zone.classList.remove('dragover');
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      handlePcapFile(files[0]);
    }
  });
  
  input.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
      handlePcapFile(e.target.files[0]);
    }
  });
}

function handlePcapFile(file) {
  if (!file.name.endsWith('.pcap')) {
    alert("Invalid File Type: ZITDA SentinelFlow only accepts standard binary network captures (.pcap).");
    return;
  }
  
  // Show file loading status
  document.getElementById('file-name-span').textContent = `${file.name} (${formatBytes(file.size)})`;
  document.getElementById('file-details').style.display = 'inline-block';
  
  const reader = new FileReader();
  reader.onload = function(e) {
    try {
      const arrayBuffer = e.target.result;
      processPcapBuffer(arrayBuffer);
    } catch (err) {
      alert(`Forensic Parse Error: ${err.message}`);
      console.error(err);
    }
  };
  reader.readAsArrayBuffer(file);
}

// ==========================================================
// 3. Demo Capture Simulation Setup
// ==========================================================
function setupSimulation() {
  const btn = document.getElementById('load-demo-btn');
  btn.addEventListener('click', () => {
    // Generate simulated ZITDA cloud cPanel threat capture
    const buffer = generateDemoPcap();
    
    document.getElementById('file-name-span').textContent = `ZITDA_Cloud_Audit_Demo.pcap (Simulated)`;
    document.getElementById('file-details').style.display = 'inline-block';
    
    processPcapBuffer(buffer);
  });
}

// ==========================================================
// 4. PCAP Process Pipeline
// ==========================================================
function processPcapBuffer(buffer) {
  // 1. Decode raw bytes
  allPackets = parsePcap(buffer);
  filteredPackets = [...allPackets];
  
  // 2. Perform threat analysis rules
  allAlerts = analyzeThreats(allPackets);
  
  // 3. Update top statistics metrics
  updateMetricsCard();
  
  // 4. Render charts
  updateCharts(allPackets, allAlerts);
  
  // 5. Render Threat alerts list
  renderAlertsBoard();
  
  // 6. Reset filters and packet list table
  currentPage = 1;
  selectedPacketId = null;
  resetFilterInputs();
  renderPacketList();
  
  // Clear inspectors
  document.getElementById('inspector-tree-container').innerHTML = `
    <p style="color: var(--text-muted); font-size: 0.85rem; font-style: italic;">
      Select a packet from the table above to view structured field values.
    </p>
  `;
  document.getElementById('hex-dump-content-div').textContent = "Select a packet to inspect binary payloads in hex and ASCII formats.";
}

function updateMetricsCard() {
  const totalPkts = allPackets.length;
  const totalVol = allPackets.reduce((acc, p) => acc + p.length, 0);
  const criticalCount = allAlerts.filter(a => a.severity === 'CRITICAL').length;
  const warningCount = allAlerts.filter(a => a.severity === 'WARNING').length;
  
  // Deduct compliance score based on alerts found
  const rawScore = 100 - (criticalCount * 15) - (warningCount * 5);
  const score = Math.max(10, rawScore);

  document.getElementById('metric-total-packets').textContent = totalPkts.toLocaleString();
  document.getElementById('metric-total-volume').textContent = formatBytes(totalVol);
  document.getElementById('metric-alerts').textContent = allAlerts.length;
  
  const scoreEl = document.getElementById('metric-score');
  scoreEl.textContent = score + "%";
  
  // Color code metric backgrounds/texts based on security level
  if (score >= 80) {
    scoreEl.style.color = 'var(--zitda-green)';
  } else if (score >= 50) {
    scoreEl.style.color = 'var(--zitda-gold)';
  } else {
    scoreEl.style.color = 'var(--zitda-crimson)';
  }

  // Update tab badge for alerts
  const badge = document.getElementById('alert-tab-badge');
  if (allAlerts.length > 0) {
    badge.textContent = allAlerts.length;
    badge.style.display = 'inline-block';
  } else {
    badge.style.display = 'none';
  }
}

// ==========================================================
// 5. Threat Alert Board Rendering
// ==========================================================
function renderAlertsBoard() {
  const container = document.getElementById('alerts-list-container');
  container.innerHTML = "";
  
  if (allAlerts.length === 0) {
    container.innerHTML = `
      <p style="color: var(--text-secondary); text-align: center; padding: 3rem;">
        No threats detected. Zamfara State Cloud infrastructure is fully compliant.
      </p>
    `;
    return;
  }
  
  allAlerts.forEach(alert => {
    const item = document.createElement('div');
    const severityClass = alert.severity.toLowerCase(); // critical / warning
    item.className = `alert-item ${severityClass}`;
    
    // Severity icon (Lucide AlertTriangle / ExclamationCircle)
    let iconSvg = '';
    if (alert.severity === 'CRITICAL') {
      iconSvg = `<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>`;
    } else {
      iconSvg = `<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>`;
    }
    
    item.innerHTML = `
      <div class="alert-severity-icon">${iconSvg}</div>
      <div class="alert-details">
        <div class="alert-header-row">
          <span class="alert-title">${alert.title}</span>
          <span class="badge ${alert.severity === 'CRITICAL' ? 'badge-danger' : 'badge-warning'}">${alert.severity}</span>
        </div>
        <div class="alert-meta" style="margin-bottom: 6px;">
          <span>Target MDA: <strong style="color: #fff">${alert.mda}</strong></span>
          <span>Source: <strong style="color: #fff">${alert.source}</strong></span>
          <span>Time: <strong>${alert.timestamp}</strong></span>
          <span style="color: var(--zitda-blue); cursor: pointer;" class="goto-packet-link" data-pkt-id="${alert.packetId}">[Jump to Packet #${alert.packetId}]</span>
        </div>
        <p class="alert-desc">${alert.description}</p>
        <div class="alert-recommendation">
          <strong>ZITDA Policy Mitigation Recommendation</strong>
          ${alert.recommendation}
        </div>
      </div>
    `;
    container.appendChild(item);
  });

  // Jump to packet click binding
  container.querySelectorAll('.goto-packet-link').forEach(link => {
    link.addEventListener('click', (e) => {
      const pktId = parseInt(e.target.dataset.pktId);
      // Navigate to forensics tab
      document.querySelector('.tab-btn[data-tab="forensics-tab"]').click();
      
      // Select packet in table
      selectedPacketId = pktId;
      
      // Search for packet's page
      const index = filteredPackets.findIndex(p => p.id === pktId);
      if (index !== -1) {
        currentPage = Math.floor(index / pageSize) + 1;
        renderPacketList();
        
        // Find and select row
        setTimeout(() => {
          const row = document.querySelector(`tr[data-packet-id="${pktId}"]`);
          if (row) {
            row.click();
            row.scrollIntoView({ behavior: 'smooth', block: 'center' });
          }
        }, 100);
      }
    });
  });
}

// ==========================================================
// 6. Forensic Packet List Rendering
// ==========================================================
function setupTableFilters() {
  const searchInput = document.getElementById('search-input');
  const protoFilter = document.getElementById('filter-protocol');
  const mdaFilter = document.getElementById('filter-mda');
  const severityFilter = document.getElementById('filter-severity');
  const resetBtn = document.getElementById('clear-filters-btn');
  
  const applyFilters = () => {
    const searchVal = searchInput.value.toLowerCase().trim();
    const protoVal = protoFilter.value;
    const mdaVal = mdaFilter.value;
    const severityVal = severityFilter.value;
    
    filteredPackets = allPackets.filter(p => {
      // 1. Search filter (matching source/dest IP or payload info string)
      const matchesSearch = !searchVal || 
        p.srcIp.toLowerCase().includes(searchVal) || 
        p.dstIp.toLowerCase().includes(searchVal) || 
        p.info.toLowerCase().includes(searchVal);
      
      // 2. Protocol filter
      const matchesProto = !protoVal || p.protocol.toUpperCase() === protoVal.toUpperCase();
      
      // 3. MDA filter
      let matchesMda = true;
      if (mdaVal) {
        const getIpFromMda = {
          'zamfara.gov.ng': '192.168.10.10',
          'finance.zm.gov.ng': '192.168.10.50',
          'judiciary.zm.gov.ng': '192.168.10.60',
          'health.zm.gov.ng': '192.168.10.70',
          'revenue.zm.gov.ng': '192.168.10.80'
        };
        const targetIp = getIpFromMda[mdaVal];
        matchesMda = p.srcIp === targetIp || p.dstIp === targetIp;
      }
      
      // 4. Severity filter (Cross-referencing alerts map)
      let matchesSeverity = true;
      if (severityVal) {
        const alertForPkt = allAlerts.find(a => a.packetId === p.id);
        if (severityVal === 'CRITICAL') matchesSeverity = alertForPkt?.severity === 'CRITICAL';
        else if (severityVal === 'WARNING') matchesSeverity = alertForPkt?.severity === 'WARNING';
        else if (severityVal === 'INFO') matchesSeverity = !alertForPkt;
      }
      
      return matchesSearch && matchesProto && matchesMda && matchesSeverity;
    });
    
    currentPage = 1;
    renderPacketList();
  };

  searchInput.addEventListener('input', applyFilters);
  protoFilter.addEventListener('change', applyFilters);
  mdaFilter.addEventListener('change', applyFilters);
  severityFilter.addEventListener('change', applyFilters);
  
  resetBtn.addEventListener('click', () => {
    resetFilterInputs();
    filteredPackets = [...allPackets];
    currentPage = 1;
    renderPacketList();
  });
  
  // Pagination navigation bindings
  document.getElementById('prev-page-btn').addEventListener('click', () => {
    if (currentPage > 1) {
      currentPage--;
      renderPacketList();
    }
  });
  
  document.getElementById('next-page-btn').addEventListener('click', () => {
    const maxPage = Math.ceil(filteredPackets.length / pageSize);
    if (currentPage < maxPage) {
      currentPage++;
      renderPacketList();
    }
  });
}

function resetFilterInputs() {
  document.getElementById('search-input').value = "";
  document.getElementById('filter-protocol').value = "";
  document.getElementById('filter-mda').value = "";
  document.getElementById('filter-severity').value = "";
}

function renderPacketList() {
  const tbody = document.getElementById('packet-list-tbody');
  tbody.innerHTML = "";
  
  if (filteredPackets.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="8" style="text-align: center; color: var(--text-secondary); padding: 3rem;">
          No packets found matching current filters.
        </td>
      </tr>
    `;
    updatePaginationControls();
    return;
  }
  
  const startIdx = (currentPage - 1) * pageSize;
  const endIdx = Math.min(startIdx + pageSize, filteredPackets.length);
  const paginatedList = filteredPackets.slice(startIdx, endIdx);
  
  paginatedList.forEach(pkt => {
    const tr = document.createElement('tr');
    tr.dataset.packetId = pkt.id;
    if (pkt.id === selectedPacketId) {
      tr.className = 'selected';
    }
    
    // Verify threat status for this packet
    const alert = allAlerts.find(a => a.packetId === pkt.id);
    let statusBadge = `<span class="badge badge-success">Clean</span>`;
    if (alert) {
      if (alert.severity === 'CRITICAL') {
        statusBadge = `<span class="badge badge-danger">Critical</span>`;
      } else {
        statusBadge = `<span class="badge badge-warning">Warning</span>`;
      }
    }
    
    tr.innerHTML = `
      <td>${pkt.id}</td>
      <td>${pkt.timestamp}</td>
      <td>${pkt.srcIp}</td>
      <td>${pkt.dstIp}</td>
      <td><span class="badge badge-info">${pkt.protocol}</span></td>
      <td>${pkt.length}</td>
      <td style="max-width: 350px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(pkt.info)}</td>
      <td>${statusBadge}</td>
    `;
    
    tr.addEventListener('click', () => {
      // Manage CSS selection styling
      tbody.querySelectorAll('tr').forEach(r => r.classList.remove('selected'));
      tr.classList.add('selected');
      selectedPacketId = pkt.id;
      
      // Load selected packet into inspectors
      renderHexDump(pkt.rawData);
      renderDecodedTree(pkt);
    });
    
    tbody.appendChild(tr);
  });
  
  updatePaginationControls();
}

function updatePaginationControls() {
  const total = filteredPackets.length;
  const maxPage = Math.max(1, Math.ceil(total / pageSize));
  
  document.getElementById('pagination-info').textContent = `Showing page ${currentPage} of ${maxPage} (${total} total packets)`;
  document.getElementById('prev-page-btn').disabled = currentPage === 1;
  document.getElementById('next-page-btn').disabled = currentPage === maxPage;
}

// ==========================================================
// 7. Forensic Inspectors (Hex Viewer & Decoded Tree)
// ==========================================================
function renderHexDump(uint8Array) {
  const display = document.getElementById('hex-dump-content-div');
  display.textContent = "";
  
  let result = "";
  for (let offset = 0; offset < uint8Array.length; offset += 16) {
    const address = offset.toString(16).padStart(4, "0");
    let hexColumns = [];
    let asciiColumn = "";
    
    for (let i = 0; i < 16; i++) {
      if (offset + i < uint8Array.length) {
        const b = uint8Array[offset + i];
        hexColumns.push(b.toString(16).padStart(2, "0"));
        
        // Printable ASCII check
        if (b >= 32 && b <= 126) {
          asciiColumn += String.fromCharCode(b);
        } else {
          asciiColumn += ".";
        }
      } else {
        hexColumns.push("  ");
        asciiColumn += " ";
      }
    }
    
    const hex1 = hexColumns.slice(0, 8).join(" ");
    const hex2 = hexColumns.slice(8, 16).join(" ");
    result += `${address}  ${hex1}  ${hex2}   | ${asciiColumn}\n`;
  }
  
  display.textContent = result;
}

function renderDecodedTree(packet) {
  const container = document.getElementById('inspector-tree-container');
  container.innerHTML = "";
  
  // Frame node
  const frameNode = createTreeDetailsNode(
    `Frame #${packet.id} (${packet.length} bytes on wire)`,
    [
      `Arrival Time: ${packet.timestamp}`,
      `Frame Number: ${packet.id}`,
      `Frame Length: ${packet.length} bytes`,
      `Protocols in Stack: ${packet.protoStack.join(" → ")}`
    ]
  );
  container.appendChild(frameNode);
  
  // Ethernet node
  if (packet.parsedFields.ethernet) {
    const eth = packet.parsedFields.ethernet;
    const ethNode = createTreeDetailsNode(
      `Ethernet II (Src: ${eth["Source MAC"]}, Dst: ${eth["Destination MAC"]})`,
      Object.keys(eth).map(k => `${k}: ${eth[k]}`)
    );
    container.appendChild(ethNode);
  }
  
  // IP node
  if (packet.parsedFields.ipv4) {
    const ip = packet.parsedFields.ipv4;
    const ipNode = createTreeDetailsNode(
      `Internet Protocol Version 4 (Src IP: ${ip["Source IP"]}, Dst IP: ${ip["Destination IP"]})`,
      Object.keys(ip).map(k => `${k}: ${ip[k]}`)
    );
    container.appendChild(ipNode);
  }
  
  // TCP node
  if (packet.parsedFields.tcp) {
    const tcp = packet.parsedFields.tcp;
    const tcpNode = createTreeDetailsNode(
      `Transmission Control Protocol (Src Port: ${tcp["Source Port"]}, Dst Port: ${tcp["Destination Port"]})`,
      Object.keys(tcp).filter(k => k !== "ASCII Payload Details").map(k => `${k}: ${tcp[k]}`)
    );
    
    if (tcp["ASCII Payload Details"]) {
      const payloadLi = document.createElement('li');
      payloadLi.style.display = 'block';
      payloadLi.style.marginTop = '6px';
      payloadLi.innerHTML = `
        <div style="font-weight: bold; margin-bottom: 2px;">Data Payload:</div>
        <pre style="background: rgba(0,0,0,0.35); padding: 0.5rem; border-radius: 4px; font-family: var(--font-mono); font-size: 0.75rem; white-space: pre-wrap; color: var(--zitda-gold); border: 1px solid rgba(245, 158, 11, 0.15);">${escapeHtml(tcp["ASCII Payload Details"])}</pre>
      `;
      tcpNode.querySelector('ul').appendChild(payloadLi);
    }
    
    container.appendChild(tcpNode);
  }
  
  // UDP node
  if (packet.parsedFields.udp) {
    const udp = packet.parsedFields.udp;
    const udpNode = createTreeDetailsNode(
      `User Datagram Protocol (Src Port: ${udp["Source Port"]}, Dst Port: ${udp["Destination Port"]})`,
      Object.keys(udp).map(k => `${k}: ${udp[k]}`)
    );
    container.appendChild(udpNode);
  }
  
  // ICMP node
  if (packet.parsedFields.icmp) {
    const icmp = packet.parsedFields.icmp;
    const icmpNode = createTreeDetailsNode(
      `Internet Control Message Protocol (Type: ${icmp["Type"]})`,
      Object.keys(icmp).map(k => `${k}: ${icmp[k]}`)
    );
    container.appendChild(icmpNode);
  }
  
  // ARP node
  if (packet.parsedFields.arp) {
    const arp = packet.parsedFields.arp;
    const arpNode = createTreeDetailsNode(
      `Address Resolution Protocol (${arp["Operation"]})`,
      Object.keys(arp).map(k => `${k}: ${arp[k]}`)
    );
    container.appendChild(arpNode);
  }
  
  // DNS node
  if (packet.parsedFields.dns) {
    const dns = packet.parsedFields.dns;
    const dnsNode = createTreeDetailsNode(
      `Domain Name System (Transaction: ${dns["Transaction ID"]})`,
      Object.keys(dns).map(k => `${k}: ${dns[k]}`)
    );
    container.appendChild(dnsNode);
  }
  
  // HTTP Payload / Header node
  if (packet.parsedFields.http) {
    const http = packet.parsedFields.http;
    const httpNode = document.createElement('details');
    httpNode.open = true;
    httpNode.className = 'tree-node';
    httpNode.innerHTML = `
      <summary class="tree-node-title">Hypertext Transfer Protocol</summary>
      <ul class="tree-node-details" style="display: block; padding: 4px 0 0 0;">
        <li>
          <pre style="background: rgba(0,0,0,0.4); border: 1px solid rgba(255,255,255,0.05); padding: 0.5rem; border-radius: 4px; font-family: var(--font-mono); font-size: 0.75rem; white-space: pre-wrap; color: var(--zitda-blue); width: 100%; overflow-x: auto;">${escapeHtml(http["Raw Request Header"])}</pre>
        </li>
      </ul>
    `;
    container.appendChild(httpNode);
  }
}

function createTreeDetailsNode(summaryText, bulletItems) {
  const details = document.createElement('details');
  details.open = true;
  details.className = 'tree-node';
  
  const summary = document.createElement('summary');
  summary.className = 'tree-node-title';
  summary.textContent = summaryText;
  
  const ul = document.createElement('ul');
  ul.className = 'tree-node-details';
  
  bulletItems.forEach(item => {
    const li = document.createElement('li');
    const [label, val] = item.split(': ');
    if (val !== undefined) {
      li.innerHTML = `<span>${escapeHtml(label)}:</span> <span style="color: #fff;">${escapeHtml(val)}</span>`;
    } else {
      li.textContent = escapeHtml(item);
    }
    ul.appendChild(li);
  });
  
  details.appendChild(summary);
  details.appendChild(ul);
  return details;
}

// ==========================================================
// 8. Forensic Compliance Report Action
// ==========================================================
function setupReportAction() {
  const btn = document.getElementById('generate-report-btn');
  btn.addEventListener('click', () => {
    if (allPackets.length === 0) {
      alert("No capture data loaded. Please upload a PCAP file or load the demo capture before compiling a compliance report.");
      return;
    }
    
    // Get form data
    const investigator = document.getElementById('report-investigator').value;
    const caseId = document.getElementById('report-case-id').value;
    const notes = document.getElementById('report-notes').value;
    
    // Generate ZITDA PDF template markup
    const reportHtml = compileForensicReport(allPackets, allAlerts, { investigator, caseId, notes });
    
    const container = document.getElementById('forensic-report-template');
    container.innerHTML = reportHtml;
    
    // Print window triggers print stylesheets (CSS is configured to hide main dashboard)
    window.print();
  });
}

// ==========================================================
// UTILITIES
// ==========================================================
function formatBytes(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function escapeHtml(str) {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
