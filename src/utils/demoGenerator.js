// ZITDA SentinelFlow PCAP Demo Generator

/**
 * Generates a valid binary PCAP byte array representing ZITDA cPanel incidents.
 * @returns {ArrayBuffer} Standard PCAP file buffer.
 */
export function generateDemoPcap() {
  const packets = [];
  let baseTime = Math.floor(Date.now() / 1000) - 3600; // 1 hour ago
  let usec = 100000;
  
  // MAC Addresses
  const gatewayMac = "00:50:56:c0:00:08";
  const portalMac = "00:0c:29:ab:cd:10";  // zamfara.gov.ng (192.168.10.10)
  const financeMac = "00:0c:29:ab:cd:50"; // finance.zm.gov.ng (192.168.10.50)
  const courtsMac = "00:0c:29:ab:cd:60";  // judiciary.zm.gov.ng (192.168.10.60)
  const healthMac = "00:0c:29:ab:cd:70";  // health.zm.gov.ng (192.168.10.70)
  const dnsMac = "00:0c:29:ab:cd:99";    // internal DNS (192.168.10.5)

  // IP Addresses
  const portalIp = "192.168.10.10";
  const financeIp = "192.168.10.50";
  const courtsIp = "192.168.10.60";
  const healthIp = "192.168.10.70";
  const internalDnsIp = "192.168.10.5";
  const externalSmtpIp = "74.125.142.27"; // External mail destination
  
  // Attacker IPs
  const scannerIp = "210.89.45.12";      // External IP (port scanner)
  const bruteForcerIp = "185.220.101.4";  // Tor exit node (cPanel brute force)
  const webAttackerIp = "198.51.100.55";  // Exploit launcher (SQL injection)
  const adminIp = "102.89.34.112";       // Gusau local admin (FTP plaintext credentials)

  // Helper: Add packet to array
  const addPacket = (macDst, macSrc, ipDst, ipSrc, proto, payload, timestampSecs, uSecs) => {
    // 1. Create packet layers
    let packetBytes;
    if (proto === "ARP") {
      packetBytes = createArpPacket(macDst, macSrc, payload);
    } else {
      let ipProto = proto === "TCP" ? 6 : proto === "UDP" ? 17 : 1;
      packetBytes = createEthernetFrame(macDst, macSrc, 0x0800, createIpPacket(ipSrc, ipDst, ipProto, payload));
    }
    
    packets.push({
      sec: timestampSecs,
      usec: uSecs,
      data: packetBytes
    });
  };

  // ==========================================================
  // SCENARIO 0: Normal Setup & DNS Query (Safe)
  // ==========================================================
  
  // Normal ARP resolution for DNS Server
  addPacket(
    "ff:ff:ff:ff:ff:ff", gatewayMac, 
    "0.0.0.0", "0.0.0.0", "ARP", 
    { op: 1, sha: gatewayMac, spa: "192.168.10.1", tha: "00:00:00:00:00:00", tpa: internalDnsIp },
    baseTime, usec
  );
  
  usec += 1500;
  addPacket(
    gatewayMac, dnsMac, 
    "0.0.0.0", "0.0.0.0", "ARP", 
    { op: 2, sha: dnsMac, spa: internalDnsIp, tha: gatewayMac, tpa: "192.168.10.1" },
    baseTime, usec
  );

  // Normal DNS request from admin workstation looking for cPanel Webmail
  usec += 50000;
  const dnsQueryBytes = createDnsPayload(0x4a1b, 0, "webmail.zamfara.gov.ng", 1); // 1 = A Record
  addPacket(
    dnsMac, gatewayMac,
    internalDnsIp, adminIp,
    "UDP", createUdpDatagram(54120, 53, dnsQueryBytes),
    baseTime, usec
  );

  // ==========================================================
  // SCENARIO 1: Port Scan Reconnaissance on main Portal
  // ==========================================================
  // External host 210.89.45.12 scanning 192.168.10.10 (cPanel / WHM ports)
  const portsToScan = [21, 22, 80, 443, 2082, 2083, 2086, 2087, 3306];
  let scanTime = baseTime + 10;
  portsToScan.forEach((port, idx) => {
    usec += 20000;
    // Send TCP SYN to port
    const synSegment = createTcpSegment(49150 + idx, port, 1000 + idx, 0, 0x02); // 0x02 = SYN
    addPacket(
      portalMac, gatewayMac,
      portalIp, scannerIp,
      "TCP", synSegment,
      scanTime, usec
    );
  });

  // ==========================================================
  // SCENARIO 2: cPanel HTTPS Brute Force Attack
  // ==========================================================
  // Tor IP 185.220.101.4 brute-forcing finance.zm.gov.ng secure cPanel (port 2083)
  let bruteTime = baseTime + 60;
  for (let i = 0; i < 8; i++) {
    usec += 100000; // 100ms apart
    
    // SYN
    const synSegment = createTcpSegment(52000 + i, 2083, 5000 + (i * 100), 0, 0x02);
    addPacket(
      financeMac, gatewayMac,
      financeIp, bruteForcerIp,
      "TCP", synSegment,
      bruteTime, usec
    );
    
    // ACK (Completing Handshake simulation)
    const ackSegment = createTcpSegment(52000 + i, 2083, 5001 + (i * 100), 120, 0x10); // ACK
    addPacket(
      financeMac, gatewayMac,
      financeIp, bruteForcerIp,
      "TCP", ackSegment,
      bruteTime, usec + 2000
    );
  }

  // ==========================================================
  // SCENARIO 3: Web App Attack (SQL Injection) on Finance Portal
  // ==========================================================
  // Exploit loader 198.51.100.55 targeting finance.zm.gov.ng over HTTP (port 80)
  let webAttackTime = baseTime + 120;
  usec += 500000;
  
  const sqlPayloadText = "GET /login.php?user=admin'%20OR%20'1'='1&pass=dump HTTP/1.1\r\nHost: finance.zm.gov.ng\r\nUser-Agent: sqlmap/1.4.12\r\nAccept: */*\r\n\r\n";
  const sqlPayloadBytes = new TextEncoder().encode(sqlPayloadText);
  const sqlTcpSegment = createTcpSegment(55432, 80, 9999, 4444, 0x18, sqlPayloadBytes); // PSH, ACK
  
  addPacket(
    financeMac, gatewayMac,
    financeIp, webAttackerIp,
    "TCP", sqlTcpSegment,
    webAttackTime, usec
  );

  // ==========================================================
  // SCENARIO 4: Cleartext FTP Administrator Login Leak
  // ==========================================================
  // Local admin 102.89.34.112 connecting to health.zm.gov.ng on port 21
  let leakTime = baseTime + 180;
  usec += 500000;
  
  // Admin sends USER command
  const ftpUserBytes = new TextEncoder().encode("USER admin_health\r\n");
  const ftpUserSegment = createTcpSegment(50210, 21, 20000, 30000, 0x18, ftpUserBytes);
  addPacket(
    healthMac, gatewayMac,
    healthIp, adminIp,
    "TCP", ftpUserSegment,
    leakTime, usec
  );

  // Admin sends PASS command
  usec += 200000;
  const ftpPassBytes = new TextEncoder().encode("PASS ZamfaraHealth2026_Secure!\r\n");
  const ftpPassSegment = createTcpSegment(50210, 21, 20000 + ftpUserBytes.length, 30000, 0x18, ftpPassBytes);
  addPacket(
    healthMac, gatewayMac,
    healthIp, adminIp,
    "TCP", ftpPassSegment,
    leakTime, usec
  );

  // ==========================================================
  // SCENARIO 5: SMTP Mail Spam Relay (Compromised account)
  // ==========================================================
  // Compromised mail server 192.168.10.60 flooding outbound SMTP relays
  let spamTime = baseTime + 240;
  for (let i = 0; i < 12; i++) {
    usec += 50000; // High rate
    
    // Connect to different mail target IPs
    const targetIp = `209.85.233.${10 + i}`;
    const smtpBytes = new TextEncoder().encode(`HELO mail.judiciary.zm.gov.ng\r\nMAIL FROM:<chief-registrar@courts.zm.gov.ng>\r\nRCPT TO:<spam-recipient-${i}@yahoo.com>\r\n`);
    const smtpSegment = createTcpSegment(25, 49200 + i, 8888, 9999, 0x18, smtpBytes);
    
    addPacket(
      gatewayMac, courtsMac,
      targetIp, courtsIp,
      "TCP", smtpSegment,
      spamTime, usec
    );
  }

  // ==========================================================
  // SCENARIO 6: Directory Traversal Web Attack on Main Portal
  // ==========================================================
  // Exploit launcher 198.51.100.55 targeting zamfara.gov.ng over HTTP (port 80)
  let traversalTime = baseTime + 280;
  usec += 500000;
  
  const traversalPayloadText = "GET /show.php?file=../../../../etc/passwd HTTP/1.1\r\nHost: zamfara.gov.ng\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n";
  const traversalPayloadBytes = new TextEncoder().encode(traversalPayloadText);
  const traversalTcpSegment = createTcpSegment(55433, 80, 10500, 5555, 0x18, traversalPayloadBytes); // PSH, ACK
  
  addPacket(
    portalMac, gatewayMac,
    portalIp, webAttackerIp,
    "TCP", traversalTcpSegment,
    traversalTime, usec
  );

  // ==========================================================
  // SCENARIO 7: Cross-Site Scripting (XSS) Attack on Main Portal
  // ==========================================================
  let xssTime = baseTime + 310;
  usec += 500000;
  
  const xssPayloadText = "GET /search.php?q=<script>alert(document.cookie)</script> HTTP/1.1\r\nHost: zamfara.gov.ng\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n";
  const xssPayloadBytes = new TextEncoder().encode(xssPayloadText);
  const xssTcpSegment = createTcpSegment(55434, 80, 11000, 6666, 0x18, xssPayloadBytes); // PSH, ACK
  
  addPacket(
    portalMac, gatewayMac,
    portalIp, webAttackerIp,
    "TCP", xssTcpSegment,
    xssTime, usec
  );

  // ==========================================================
  // SCENARIO 8: ICMP Ping Flood DDoS Attack on Finance server
  // ==========================================================
  // Attacker 203.0.113.88 floods finance server 192.168.10.50 with ICMP requests
  let icmpFloodTime = baseTime + 340;
  const icmpAttackerIp = "203.0.113.88";
  
  for (let i = 0; i < 16; i++) {
    usec += 10000; // 10ms intervals
    
    // Create an ICMP payload (Type 8 = Echo Request, Code 0)
    const icmpBytes = new Uint8Array(32);
    icmpBytes[0] = 8; // Type: Echo Request
    icmpBytes[1] = 0; // Code: 0
    icmpBytes[2] = 0; icmpBytes[3] = 0; // Checksum (dummy)
    icmpBytes[4] = 0x12; icmpBytes[5] = 0x34; // Identifier
    icmpBytes[6] = 0x00; icmpBytes[7] = i; // Sequence number
    
    // Fill payload
    for (let j = 8; j < 32; j++) {
      icmpBytes[j] = j;
    }
    
    addPacket(
      financeMac, gatewayMac,
      financeIp, icmpAttackerIp,
      "ICMP", icmpBytes,
      icmpFloodTime, usec
    );
  }

  // ==========================================================
  // COMPILE PACKETS INTO RAW PCAP BYTE STREAM
  // ==========================================================
  
  // Calculate total buffer size needed
  let totalBytes = 24; // Global header
  packets.forEach(p => {
    totalBytes += 16 + p.data.length; // Packet header (16) + Packet data
  });
  
  const buffer = new ArrayBuffer(totalBytes);
  const view = new DataView(buffer);
  const u8 = new Uint8Array(buffer);
  
  // 1. Write PCAP Global Header
  view.setUint32(0, 0xd4c3b2a1, true); // Magic (Little Endian)
  view.setUint16(4, 2, true);          // Version Major
  view.setUint16(6, 4, true);          // Version Minor
  view.setUint32(8, 0, true);          // GMT Offset
  view.setUint32(12, 0, true);         // Accuracy
  view.setUint32(16, 65535, true);     // Snaplen
  view.setUint32(20, 1, true);         // Link Type: Ethernet (1)
  
  // 2. Write Packet Data
  let offset = 24;
  packets.forEach(p => {
    view.setUint32(offset, p.sec, true);
    view.setUint32(offset + 4, p.usec, true);
    view.setUint32(offset + 8, p.data.length, true); // incl_len
    view.setUint32(offset + 12, p.data.length, true); // orig_len
    
    offset += 16;
    u8.set(p.data, offset);
    offset += p.data.length;
  });
  
  return buffer;
}

// ============================================================
// LOW LEVEL PACKET GENERATOR HELPERS
// ============================================================

function createEthernetFrame(dstMac, srcMac, etherType, payload) {
  const frame = new Uint8Array(14 + payload.length);
  parseMac(dstMac, frame, 0);
  parseMac(srcMac, frame, 6);
  frame[12] = (etherType >> 8) & 0xff;
  frame[13] = etherType & 0xff;
  frame.set(payload, 14);
  return frame;
}

function parseMac(macStr, outArray, offset) {
  const parts = macStr.split(":").map(x => parseInt(x, 16));
  for (let i = 0; i < 6; i++) {
    outArray[offset + i] = parts[i];
  }
}

function createIpPacket(srcIp, dstIp, protocol, payload) {
  const ip = new Uint8Array(20 + payload.length);
  ip[0] = 0x45; // IPv4, Header Length = 20 bytes
  ip[1] = 0x00; // TOS
  const totalLen = 20 + payload.length;
  ip[2] = (totalLen >> 8) & 0xff;
  ip[3] = totalLen & 0xff;
  ip[4] = 0x2b; ip[5] = 0x3d; // Identification
  ip[6] = 0x40; ip[7] = 0x00; // Flags: DF
  ip[8] = 128; // TTL
  ip[9] = protocol;
  ip[10] = 0x00; ip[11] = 0x00; // Header Checksum (Uncalculated dummy)
  
  parseIp(srcIp, ip, 12);
  parseIp(dstIp, ip, 16);
  
  ip.set(payload, 20);
  return ip;
}

function parseIp(ipStr, outArray, offset) {
  const parts = ipStr.split(".").map(x => parseInt(x));
  for (let i = 0; i < 4; i++) {
    outArray[offset + i] = parts[i];
  }
}

function createTcpSegment(srcPort, dstPort, seq, ack, flags, payload = new Uint8Array(0)) {
  const tcp = new Uint8Array(20 + payload.length);
  tcp[0] = (srcPort >> 8) & 0xff;
  tcp[1] = srcPort & 0xff;
  tcp[2] = (dstPort >> 8) & 0xff;
  tcp[3] = dstPort & 0xff;
  
  // Sequence number
  tcp[4] = (seq >> 24) & 0xff;
  tcp[5] = (seq >> 16) & 0xff;
  tcp[6] = (seq >> 8) & 0xff;
  tcp[7] = seq & 0xff;
  
  // Acknowledgment number
  tcp[8] = (ack >> 24) & 0xff;
  tcp[9] = (ack >> 16) & 0xff;
  tcp[10] = (ack >> 8) & 0xff;
  tcp[11] = ack & 0xff;
  
  tcp[12] = 0x50; // Data Offset = 20 bytes (5 words), Reserved
  tcp[13] = flags; // Control Flags
  tcp[14] = 0x7f; tcp[15] = 0xff; // Window Size
  tcp[16] = 0x00; tcp[17] = 0x00; // Checksum
  tcp[18] = 0x00; tcp[19] = 0x00; // Urgent Pointer
  
  tcp.set(payload, 20);
  return tcp;
}

function createUdpDatagram(srcPort, dstPort, payload) {
  const udp = new Uint8Array(8 + payload.length);
  udp[0] = (srcPort >> 8) & 0xff;
  udp[1] = srcPort & 0xff;
  udp[2] = (dstPort >> 8) & 0xff;
  udp[3] = dstPort & 0xff;
  
  const len = 8 + payload.length;
  udp[4] = (len >> 8) & 0xff;
  udp[5] = len & 0xff;
  udp[6] = 0x00; udp[7] = 0x00; // Checksum
  
  udp.set(payload, 8);
  return udp;
}

function createArpPacket(macDst, macSrc, details) {
  // ARP payload is 28 bytes. Total packet is 14 (Ethernet) + 28 = 42 bytes.
  const arp = new Uint8Array(28);
  // Hardware Type: Ethernet (0x0001)
  arp[0] = 0x00; arp[1] = 0x01;
  // Protocol Type: IPv4 (0x0800)
  arp[2] = 0x08; arp[3] = 0x00;
  // Hardware Size (6), Protocol Size (4)
  arp[4] = 6; arp[5] = 4;
  // Operation (1 = Request, 2 = Reply)
  arp[6] = 0x00; arp[7] = details.op;
  
  // Addresses
  parseMac(details.sha, arp, 8);
  parseIp(details.spa, arp, 14);
  parseMac(details.tha, arp, 18);
  parseIp(details.tpa, arp, 24);
  
  return createEthernetFrame(macDst, macSrc, 0x0806, arp);
}

function createDnsPayload(id, qr, queryName, qtype) {
  const header = new Uint8Array(12);
  header[0] = (id >> 8) & 0xff;
  header[1] = id & 0xff;
  header[2] = qr === 0 ? 0x01 : 0x81; // Query vs Response
  header[3] = 0x00;
  header[4] = 0x00; header[5] = 0x01; //qdcount = 1
  header[6] = 0x00; header[7] = 0x00; //ancount = 0
  
  const labels = queryName.split(".");
  const nameBytes = [];
  labels.forEach(lbl => {
    nameBytes.push(lbl.length);
    for (let i = 0; i < lbl.length; i++) {
      nameBytes.push(lbl.charCodeAt(i));
    }
  });
  nameBytes.push(0); // Null terminator
  
  const trailer = new Uint8Array([
    (qtype >> 8) & 0xff, qtype & 0xff, // qtype
    0x00, 0x01                        // qclass (IN)
  ]);
  
  const total = new Uint8Array(header.length + nameBytes.length + trailer.length);
  total.set(header, 0);
  total.set(new Uint8Array(nameBytes), header.length);
  total.set(trailer, header.length + nameBytes.length);
  return total;
}
