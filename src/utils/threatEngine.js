// ZITDA SentinelFlow Threat Detection Engine

/**
 * Analyzes parsed packets and returns list of triggered security alerts.
 * @param {Array[]} packets 
 * @returns {Array[]} List of alert objects.
 */
export function analyzeThreats(packets) {
  const alerts = [];
  
  // Trackers for heuristics
  const portScanTracker = {}; // srcIp -> Set(dstPorts)
  const bruteForceTracker = {}; // srcIp + ":" + dstPort -> { count: 0, timestamps: [], packets: [] }
  const smtpTracker = {}; // srcIp -> { count: 0, packets: [] }
  const icmpTracker = {}; // srcIp -> { count: 0, targetIp: "", packets: [] }
  
  // Custom helper to convert Uint8Array payload to String
  const getPayloadString = (packet) => {
    if (!packet.payload || packet.payload.length === 0) return "";
    let str = "";
    for (let i = 0; i < packet.payload.length; i++) {
      const c = packet.payload[i];
      if ((c >= 32 && c <= 126) || c === 10 || c === 13) {
        str += String.fromCharCode(c);
      }
    }
    return str;
  };

  // Map IP to ZITDA MDA subdomains (representing Zamfara State departments)
  const getMdaName = (ip) => {
    if (ip.startsWith("192.168.10.")) {
      const lastOctet = parseInt(ip.split(".")[3]);
      if (lastOctet === 50) return "finance.zm.gov.ng (Ministry of Finance)";
      if (lastOctet === 60) return "judiciary.zm.gov.ng (State Courts)";
      if (lastOctet === 70) return "health.zm.gov.ng (Health Management Board)";
      if (lastOctet === 80) return "revenue.zm.gov.ng (Internal Revenue Service)";
    }
    if (ip === "192.168.10.10") return "zamfara.gov.ng (Main State Portal)";
    return "External Host / Cloud VM";
  };

  packets.forEach(pkt => {
    const srcIp = pkt.srcIp;
    const dstIp = pkt.dstIp;
    const proto = pkt.protocol;
    
    // Check TCP/UDP ports
    let srcPort = 0, dstPort = 0;
    if (pkt.parsedFields?.tcp) {
      srcPort = pkt.parsedFields.tcp["Source Port"];
      dstPort = pkt.parsedFields.tcp["Destination Port"];
    } else if (pkt.parsedFields?.udp) {
      srcPort = pkt.parsedFields.udp["Source Port"];
      dstPort = pkt.parsedFields.udp["Destination Port"];
    }
    
    // ----------------------------------------------------
    // 1. Port Scanning Heuristics (Network Discovery)
    // ----------------------------------------------------
    if (srcIp !== "N/A" && dstIp !== "N/A" && dstPort > 0) {
      // Exclude standard outbound traffic from government IPs
      if (!srcIp.startsWith("192.168.10.")) {
        if (!portScanTracker[srcIp]) {
          portScanTracker[srcIp] = {
            ports: new Set(),
            targetIp: dstIp,
            packetIds: []
          };
        }
        portScanTracker[srcIp].ports.add(dstPort);
        portScanTracker[srcIp].packetIds.push(pkt.id);
      }
    }

    // ----------------------------------------------------
    // 2. cPanel / WHM / SSH Brute Force Detection
    // ----------------------------------------------------
    const brutePorts = [22, 21, 2082, 2083, 2086, 2087];
    if (brutePorts.includes(dstPort) && srcIp !== "N/A") {
      const key = `${srcIp}:${dstPort}`;
      if (!bruteForceTracker[key]) {
        bruteForceTracker[key] = {
          count: 0,
          packets: []
        };
      }
      bruteForceTracker[key].count++;
      bruteForceTracker[key].packets.push(pkt);
    }

    // ----------------------------------------------------
    // 3. Cleartext Credentials Leakage
    // ----------------------------------------------------
    const unencryptedPorts = [21, 2082, 2086]; // FTP, cPanel HTTP, WHM HTTP
    if (unencryptedPorts.includes(dstPort) || unencryptedPorts.includes(srcPort)) {
      const payload = getPayloadString(pkt);
      
      // Check FTP credentials
      if (payload.includes("USER ") || payload.includes("PASS ")) {
        const lines = payload.split(/\r?\n/);
        let username = "";
        let passwordDetected = false;
        
        lines.forEach(line => {
          if (line.startsWith("USER ")) {
            username = line.substring(5).trim();
          }
          if (line.startsWith("PASS ")) {
            passwordDetected = true;
          }
        });
        
        if (username || passwordDetected) {
          alerts.push({
            id: `leak-${pkt.id}`,
            severity: "CRITICAL",
            title: "Cleartext FTP Admin Credentials Leaked",
            category: "Identity Exposure",
            mda: getMdaName(dstIp),
            source: srcIp,
            destination: dstIp,
            timestamp: pkt.timestamp,
            packetId: pkt.id,
            description: `Administrative session on unencrypted FTP (port 21) leaked credentials. Username: "${username || "Unknown"}", password transfer detected in plain text.`,
            recommendation: "ZITDA Policy Mandate: Immediately disable unencrypted FTP (port 21). Migrate all MDA administrators to SFTP (port 22) or FTPS (FTP over TLS) and rotate the compromised password."
          });
        }
      }
      
      // Check cPanel unencrypted logins
      if (payload.includes("user=") || payload.includes("pass=") || payload.includes("password=")) {
        alerts.push({
          id: `leak-cpanel-${pkt.id}`,
          severity: "CRITICAL",
          title: "Unsecured cPanel Login Session",
          category: "Credential Theft",
          mda: getMdaName(dstIp),
          source: srcIp,
          destination: dstIp,
          timestamp: pkt.timestamp,
          packetId: pkt.id,
          description: `An administrator connected to cPanel via HTTP (Port 2082) instead of HTTPS (Port 2083). Login parameters containing credentials were detected in clear text in the packet payload.`,
          recommendation: "ZITDA Compliance Directive: Enforce WHM settings to automatically redirect all cPanel administrative connections to HTTPS ports (2083 for cPanel, 2087 for WHM). Ensure Port 2082 and 2086 are blocked at the state gateway firewall."
        });
      }
    }

    // ----------------------------------------------------
    // 4. SQL Injection (SQLi) Web Attack
    // ----------------------------------------------------
    if (proto === "HTTP" && (dstPort === 80 || dstPort === 443)) {
      const payload = getPayloadString(pkt);
      const sqliPatterns = [
        /UNION\s+SELECT/i,
        /SELECT\s+.*\s+FROM/i,
        /'\s*OR\s*'\d+'\s*=\s*'\d+/i,
        /OR\s+1\s*=\s*1/i,
        /INFORMATION_SCHEMA/i,
        /DROP\s+TABLE/i,
        /sysdatabases/i
      ];
      
      const matched = sqliPatterns.some(pattern => pattern.test(payload));
      if (matched) {
        alerts.push({
          id: `sqli-${pkt.id}`,
          severity: "CRITICAL",
          title: "SQL Injection Web Exploit Attempt",
          category: "Application Attack",
          mda: getMdaName(dstIp),
          source: srcIp,
          destination: dstIp,
          timestamp: pkt.timestamp,
          packetId: pkt.id,
          description: `Web traffic targeting Zamfara MDA website contains SQL Injection strings in the payload (e.g. "1=1" logic or UNION SELECT directives). Target host: ${dstIp} (${getMdaName(dstIp)}).`,
          recommendation: "ZITDA WAF Action: Update the Web Application Firewall (WAF) rule signatures to block this payload. Enable input sanitization and parameterized queries on all government web PHP scripts in cPanel hosting."
        });
      }
    }

    // ----------------------------------------------------
    // 5. Unencrypted Administration Channels
    // ----------------------------------------------------
    if ([2082, 2086].includes(dstPort)) {
      alerts.push({
        id: `unsecured-admin-${pkt.id}`,
        severity: "WARNING",
        title: "Unencrypted Administration Channel Active",
        category: "Policy Violation",
        mda: getMdaName(dstIp),
        source: srcIp,
        destination: dstIp,
        timestamp: pkt.timestamp,
        packetId: pkt.id,
        description: `Administrator accessed cloud control panel using unencrypted port ${dstPort} (cPanel HTTP). All session details and settings are visible to sniffing.`,
        recommendation: "ZITDA Policy Compliance: Configure cPanel/WHM 'Tweak Settings' to redirect all WHM/cPanel logins to secure SSL/TLS ports (2083 / 2087)."
      });
    }

    // ----------------------------------------------------
    // 6. SMTP Mail Relay / Spamming Heuristics
    // ----------------------------------------------------
    const smtpPorts = [25, 465, 587];
    if (smtpPorts.includes(dstPort) && srcIp.startsWith("192.168.10.")) {
      if (!smtpTracker[srcIp]) {
        smtpTracker[srcIp] = {
          count: 0,
          packets: []
        };
      }
      smtpTracker[srcIp].count++;
      smtpTracker[srcIp].packets.push(pkt);
    }

    // ----------------------------------------------------
    // 7. Cross-Site Scripting (XSS) Web Attack Detection
    // ----------------------------------------------------
    if (proto === "HTTP" && (dstPort === 80 || dstPort === 443)) {
      const payload = getPayloadString(pkt);
      const xssPatterns = [
        /<script\b[^>]*>/i,
        /javascript:/i,
        /onerror\s*=/i,
        /onload\s*=/i,
        /eval\s*\(/i,
        /document\.cookie/i,
        /<iframe\b[^>]*>/i
      ];
      const matched = xssPatterns.some(pattern => pattern.test(payload));
      if (matched) {
        alerts.push({
          id: `xss-${pkt.id}`,
          severity: "CRITICAL",
          title: "Cross-Site Scripting (XSS) Attack Attempt",
          category: "Application Attack",
          mda: getMdaName(dstIp),
          source: srcIp,
          destination: dstIp,
          timestamp: pkt.timestamp,
          packetId: pkt.id,
          description: `Web traffic targeting Zamfara MDA website contains suspicious Cross-Site Scripting (XSS) payload signatures (e.g., inline scripting tags or script handlers) in the request payload. Target host: ${dstIp} (${getMdaName(dstIp)}).`,
          recommendation: "ZITDA Security Mandate: Ensure the Web Application Firewall (WAF) blocks request payloads containing HTML tag injections and inline javascript. Implement context-aware output encoding (HTML, Javascript, Attribute) on all dynamic government web components."
        });
      }
    }

    // ----------------------------------------------------
    // 8. Directory Traversal Attack Detection
    // ----------------------------------------------------
    if (proto === "HTTP" && (dstPort === 80 || dstPort === 443)) {
      const payload = getPayloadString(pkt);
      const traversalPatterns = [
        /\.\.\//,                // ../
        /\.\.%2f/i,              // ..%2f
        /\.\.\\/,                // ..\
        /etc\/passwd/i,
        /etc\/shadow/i,
        /win\.ini/i,
        /boot\.ini/i
      ];
      const matched = traversalPatterns.some(pattern => pattern.test(payload));
      if (matched) {
        alerts.push({
          id: `traversal-${pkt.id}`,
          severity: "CRITICAL",
          title: "Directory Traversal Exploit Attempt",
          category: "Application Attack",
          mda: getMdaName(dstIp),
          source: srcIp,
          destination: dstIp,
          timestamp: pkt.timestamp,
          packetId: pkt.id,
          description: `An external host attempted a Directory Traversal attack on a government web application by requesting files outside the document root directory (detected sequence: "../" or access to restricted OS files). Target host: ${dstIp} (${getMdaName(dstIp)}).`,
          recommendation: "ZITDA Security Mandate: Enforce proper access controls and file permissions on cPanel web roots. Disable directory listing, run web processes under low-privilege accounts, and use normalized path checks in all web application file operations."
        });
      }
    }

    // ----------------------------------------------------
    // 9. ICMP Ping Traffic Tracking
    // ----------------------------------------------------
    if (proto === "ICMP" && srcIp !== "N/A" && dstIp !== "N/A") {
      if (!icmpTracker[srcIp]) {
        icmpTracker[srcIp] = {
          count: 0,
          targetIp: dstIp,
          packets: []
        };
      }
      icmpTracker[srcIp].count++;
      icmpTracker[srcIp].packets.push(pkt);
    }
  });

  // Evaluate aggregated trackers to trigger alert events

  // 1. Port Scan triggers
  Object.keys(portScanTracker).forEach(srcIp => {
    const info = portScanTracker[srcIp];
    if (info.ports.size >= 5) {
      alerts.push({
        id: `scan-${srcIp}`,
        severity: "WARNING",
        title: "Network Port Scanning Detected",
        category: "Reconnaissance",
        mda: getMdaName(info.targetIp),
        source: srcIp,
        destination: info.targetIp,
        timestamp: packets[0]?.timestamp || "N/A",
        packetId: info.packetIds[0],
        description: `External host ${srcIp} queried ${info.ports.size} distinct ports on state server ${info.targetIp} (${getMdaName(info.targetIp)}) in a short duration.`,
        recommendation: "ZITDA Gateway Rule: Configure the State edge firewall to drop all TCP traffic from this source IP address. Implement network-level rate limits on SYN scans."
      });
    }
  });

  // 2. Brute Force triggers
  Object.keys(bruteForceTracker).forEach(key => {
    const tracker = bruteForceTracker[key];
    const [srcIp, port] = key.split(":");
    const dstPort = parseInt(port);
    
    // Trigger if there are more than 6 connection attempts on a secure portal
    if (tracker.count >= 6) {
      const portNames = {
        22: "SSH (Terminal)",
        21: "FTP (File Admin)",
        2082: "cPanel HTTP",
        2083: "cPanel HTTPS",
        2086: "WHM HTTP",
        2087: "WHM HTTPS"
      };
      const serviceName = portNames[dstPort] || `Port ${dstPort}`;
      const firstPkt = tracker.packets[0];
      
      alerts.push({
        id: `brute-${key}`,
        severity: "CRITICAL",
        title: `cPanel Service Brute-Force Attack`,
        category: "Credential Cracking",
        mda: getMdaName(firstPkt.dstIp),
        source: srcIp,
        destination: firstPkt.dstIp,
        timestamp: firstPkt.timestamp,
        packetId: firstPkt.id,
        description: `Source IP ${srcIp} launched ${tracker.count} authentication connection attempts against ${serviceName} on state server ${firstPkt.dstIp} (${getMdaName(firstPkt.dstIp)}).`,
        recommendation: "ZITDA cPanel Security: Enable cPanel 'cPHulk Brute Force Protection' in Web Host Manager (WHM). Configure block thresholds to lock out IPs after 5 failed authentication attempts, and whitelist official ZITDA IP ranges."
      });
    }
  });

  // 3. SMTP Mail Spam triggers
  Object.keys(smtpTracker).forEach(srcIp => {
    const tracker = smtpTracker[srcIp];
    const firstPkt = tracker.packets[0];
    
    // High count of SMTP transactions indicates automated outbound spam mail relay
    if (tracker.count >= 10) {
      alerts.push({
        id: `spam-${srcIp}`,
        severity: "CRITICAL",
        title: "SMTP Mail Spam Relay Activity",
        category: "Hijacked Account",
        mda: getMdaName(srcIp),
        source: srcIp,
        destination: "External Mail Relay",
        timestamp: firstPkt.timestamp,
        packetId: firstPkt.id,
        description: `State server IP ${srcIp} (${getMdaName(srcIp)}) initiated ${tracker.count} high-volume outbound mail handshakes on port 25/465. This strongly suggests a government email account on cPanel hosting has been compromised and is serving as an open spam relay.`,
        recommendation: "ZITDA Mail Audit: Immediately suspend the sending cPanel account. Inspect cPanel EXIM mail logs to find the authenticated username sending these emails. Enforce strong password policies for government mailboxes and verify SPF, DKIM, and DMARC settings."
      });
    }
  });

  // 4. ICMP Flood / DDoS triggers
  Object.keys(icmpTracker).forEach(srcIp => {
    const tracker = icmpTracker[srcIp];
    if (tracker.count >= 15) {
      const firstPkt = tracker.packets[0];
      alerts.push({
        id: `icmp-flood-${srcIp}`,
        severity: "CRITICAL",
        title: "ICMP Ping Flood (DDoS) Detected",
        category: "Denial of Service",
        mda: getMdaName(tracker.targetIp),
        source: srcIp,
        destination: tracker.targetIp,
        timestamp: firstPkt.timestamp,
        packetId: firstPkt.id,
        description: `External host ${srcIp} is flooding the government cloud server ${tracker.targetIp} (${getMdaName(tracker.targetIp)}) with an excessive volume of ICMP Echo Request packets (${tracker.count} pings in a short window). This is characteristic of a Ping Flood Denial of Service (DDoS) attack attempting to exhaust server network resources.`,
        recommendation: "ZITDA Edge Firewall Directive: Implement rate-limiting on incoming ICMP traffic at the network edge router. Configure edge firewalls to ignore ICMP requests (block echo requests) during peak traffic anomalies, or permanently drop echo requests from non-essential subnets."
      });
    }
  });

  // Sort alerts chronologically
  return alerts.sort((a, b) => a.packetId - b.packetId);
}
