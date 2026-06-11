// ZITDA SentinelFlow Binary PCAP Parser

/**
 * Parses a binary PCAP ArrayBuffer into structured packet objects.
 * @param {ArrayBuffer} arrayBuffer 
 * @returns {Array[]} List of decoded packets.
 */
export function parsePcap(arrayBuffer) {
  const view = new DataView(arrayBuffer);
  const u8 = new Uint8Array(arrayBuffer);
  
  if (arrayBuffer.byteLength < 24) {
    throw new Error("Invalid PCAP file: File is too small to contain global header.");
  }
  
  // Read PCAP Magic Number to determine Endianness
  const magic = view.getUint32(0, true);
  let littleEndian = true;
  
  if (magic === 0xa1b2c3d4) {
    littleEndian = false;
  } else if (magic === 0xd4c3b2a1) {
    littleEndian = true;
  } else if (magic === 0xa1b23c4d) {
    littleEndian = false; // Nanosecond resolution
  } else if (magic === 0x4d3cb2a1) {
    littleEndian = true; // Nanosecond resolution
  } else {
    throw new Error("Invalid PCAP file: Unknown magic number. Not a standard PCAP file.");
  }
  
  const network = view.getUint32(20, littleEndian);
  
  let offset = 24;
  const packets = [];
  let packetId = 1;
  
  // Parse packets sequentially
  while (offset + 16 <= arrayBuffer.byteLength) {
    const tsSec = view.getUint32(offset, littleEndian);
    const tsUsec = view.getUint32(offset + 4, littleEndian);
    const inclLen = view.getUint32(offset + 8, littleEndian);
    const origLen = view.getUint32(offset + 12, littleEndian);
    
    offset += 16;
    
    if (offset + inclLen > arrayBuffer.byteLength) {
      // Truncated packet at end of capture
      break;
    }
    
    const packetData = u8.subarray(offset, offset + inclLen);
    
    try {
      // Decode based on Link Type (Ethernet Link Type = 1 is standard)
      const parsed = decodePacket(packetData, packetId, tsSec, tsUsec, network);
      if (parsed) {
        packets.push(parsed);
      }
    } catch (err) {
      console.warn(`Error parsing packet ${packetId} at offset ${offset}:`, err);
    }
    
    packetId++;
    offset += inclLen;
  }
  
  return packets;
}

/**
 * Decodes a single raw packet byte segment.
 */
function decodePacket(data, id, tsSec, tsUsec, linkType) {
  // Standard PCAPs use LinkType = 1 (Ethernet). Let's check for Ethernet header.
  if (data.length < 14) return null;
  
  const dstMac = formatMac(data.subarray(0, 6));
  const srcMac = formatMac(data.subarray(6, 12));
  const etherType = (data[12] << 8) | data[13];
  
  let payloadOffset = 14;
  let protoStack = ["Ethernet"];
  let srcIp = "N/A";
  let dstIp = "N/A";
  let protocol = "Ethernet";
  let srcPort = 0;
  let dstPort = 0;
  let info = `Ethernet Frame: ${srcMac} → ${dstMac}`;
  let payloadBytes = null;
  
  let parsedFields = {
    ethernet: {
      "Destination MAC": dstMac,
      "Source MAC": srcMac,
      "Type": "0x" + etherType.toString(16).padStart(4, "0") + (etherType === 0x0800 ? " (IPv4)" : etherType === 0x0806 ? " (ARP)" : "")
    }
  };
  
  if (etherType === 0x0800) { // IPv4
    protocol = "IPv4";
    protoStack.push("IPv4");
    if (data.length < 14 + 20) return null;
    
    const versionIhl = data[14];
    const version = versionIhl >> 4;
    const ihl = versionIhl & 0x0f;
    const ipHeaderLen = ihl * 4;
    
    if (data.length < 14 + ipHeaderLen) return null;
    
    const totalLen = (data[16] << 8) | data[17];
    const ttl = data[22];
    const ipProto = data[23];
    
    srcIp = `${data[26]}.${data[27]}.${data[28]}.${data[29]}`;
    dstIp = `${data[30]}.${data[31]}.${data[32]}.${data[33]}`;
    
    let protoName = ipProto === 6 ? "TCP" : ipProto === 17 ? "UDP" : ipProto === 1 ? "ICMP" : "Proto-" + ipProto;
    
    parsedFields.ipv4 = {
      "Version": version,
      "Header Length": `${ipHeaderLen} bytes`,
      "Total Length": `${totalLen} bytes`,
      "TTL": ttl,
      "Protocol": `${ipProto} (${protoName})`,
      "Source IP": srcIp,
      "Destination IP": dstIp
    };
    
    payloadOffset = 14 + ipHeaderLen;
    
    if (ipProto === 6) { // TCP
      protocol = "TCP";
      protoStack.push("TCP");
      if (data.length < payloadOffset + 20) return null;
      
      srcPort = (data[payloadOffset] << 8) | data[payloadOffset + 1];
      dstPort = (data[payloadOffset + 2] << 8) | data[payloadOffset + 3];
      const seqNum = ((data[payloadOffset + 4] << 24) | (data[payloadOffset + 5] << 16) | (data[payloadOffset + 6] << 8) | data[payloadOffset + 7]) >>> 0;
      const ackNum = ((data[payloadOffset + 8] << 24) | (data[payloadOffset + 9] << 16) | (data[payloadOffset + 10] << 8) | data[payloadOffset + 11]) >>> 0;
      const dataOffset = (data[payloadOffset + 12] >> 4) * 4;
      const flags = data[payloadOffset + 13];
      
      const syn = !!(flags & 0x02);
      const ack = !!(flags & 0x10);
      const fin = !!(flags & 0x01);
      const rst = !!(flags & 0x04);
      const psh = !!(flags & 0x08);
      
      let flagsStr = [];
      if (syn) flagsStr.push("SYN");
      if (ack) flagsStr.push("ACK");
      if (fin) flagsStr.push("FIN");
      if (rst) flagsStr.push("RST");
      if (psh) flagsStr.push("PSH");
      
      parsedFields.tcp = {
        "Source Port": srcPort,
        "Destination Port": dstPort,
        "Sequence Number": seqNum,
        "Acknowledgment Number": ackNum,
        "Flags": `0x${flags.toString(16).padStart(2, "0")} (${flagsStr.join(", ")})`,
        "Header Length": `${dataOffset} bytes`
      };
      
      const tcpPayloadOffset = payloadOffset + dataOffset;
      if (data.length > tcpPayloadOffset) {
        payloadBytes = data.subarray(tcpPayloadOffset);
      }
      
      info = `${srcPort} → ${dstPort} [${flagsStr.join(", ")}] Seq=${seqNum} Ack=${ackNum}`;
      
      // Categorize cPanel, Webmail, WHM, SSH, and DB ports
      if (srcPort === 2083 || dstPort === 2083) {
        protocol = "cPanel";
        info = `cPanel Admin Session Secure [${flagsStr.join(", ")}]`;
      } else if (srcPort === 2082 || dstPort === 2082) {
        protocol = "cPanel";
        info = `cPanel Admin Session UNENCRYPTED [${flagsStr.join(", ")}]`;
      } else if (srcPort === 2087 || dstPort === 2087) {
        protocol = "WHM";
        info = `WHM Admin Console Secure [${flagsStr.join(", ")}]`;
      } else if (srcPort === 2086 || dstPort === 2086) {
        protocol = "WHM";
        info = `WHM Admin Console UNENCRYPTED [${flagsStr.join(", ")}]`;
      } else if (srcPort === 2096 || dstPort === 2096) {
        protocol = "Webmail";
        info = `Secure Webmail portal access`;
      } else if (srcPort === 2095 || dstPort === 2095) {
        protocol = "Webmail";
        info = `UNENCRYPTED Webmail portal access`;
      } else if (srcPort === 22 || dstPort === 22) {
        protocol = "SSH";
        info = `SSH Remote Shell Access [Port 22]`;
      } else if (srcPort === 21 || dstPort === 21) {
        protocol = "FTP";
        info = `FTP Administrative File Transfer [Unencrypted]`;
      } else if (srcPort === 3306 || dstPort === 3306) {
        protocol = "MySQL";
        info = `MySQL Database connection`;
      } else if (srcPort === 25 || dstPort === 25 || srcPort === 465 || dstPort === 465 || srcPort === 587 || dstPort === 587) {
        protocol = "SMTP";
        info = `SMTP Mail Transfer Session`;
      } else if (srcPort === 80 || dstPort === 80 || srcPort === 443 || dstPort === 443) {
        protocol = "HTTP";
        if (payloadBytes && payloadBytes.length > 0) {
          const text = bytesToAscii(payloadBytes);
          if (text.startsWith("GET") || text.startsWith("POST") || text.startsWith("HTTP")) {
            const firstLine = text.split("\r\n")[0];
            info = firstLine;
            parsedFields.http = {
              "Raw Request Header": text.substring(0, 500)
            };
          }
        }
      }
      
      // Parse plain text HTTP request for FTP / cPanel passwords in demo
      if (payloadBytes && payloadBytes.length > 0) {
        const text = bytesToAscii(payloadBytes);
        if (text.includes("USER") || text.includes("PASS") || text.includes("user=") || text.includes("pass=")) {
          parsedFields.tcp["ASCII Payload Details"] = text.substring(0, 300);
        }
      }
      
    } else if (ipProto === 17) { // UDP
      protocol = "UDP";
      protoStack.push("UDP");
      if (data.length < payloadOffset + 8) return null;
      
      srcPort = (data[payloadOffset] << 8) | data[payloadOffset + 1];
      dstPort = (data[payloadOffset + 2] << 8) | data[payloadOffset + 3];
      const length = (data[payloadOffset + 4] << 8) | data[payloadOffset + 5];
      
      parsedFields.udp = {
        "Source Port": srcPort,
        "Destination Port": dstPort,
        "Length": `${length} bytes`
      };
      
      const udpPayloadOffset = payloadOffset + 8;
      if (data.length > udpPayloadOffset) {
        payloadBytes = data.subarray(udpPayloadOffset);
      }
      
      info = `${srcPort} → ${dstPort} Len=${length}`;
      
      if (srcPort === 53 || dstPort === 53) {
        protocol = "DNS";
        protoStack.push("DNS");
        
        if (payloadBytes && payloadBytes.length > 0) {
          try {
            const dns = parseDnsPayload(payloadBytes);
            if (dns) {
              info = `DNS ${dns.direction}: ${dns.queryName} (${dns.queryType})`;
              parsedFields.dns = {
                "Transaction ID": dns.transactionId,
                "Type": dns.direction,
                "Query Name": dns.queryName,
                "Query Type": dns.queryType
              };
            }
          } catch (e) {
            info = "DNS Query [Malformed]";
          }
        }
      }
    } else if (ipProto === 1) { // ICMP
      protocol = "ICMP";
      protoStack.push("ICMP");
      info = "ICMP Ping Request/Reply";
      
      if (data.length >= payloadOffset + 2) {
        const icmpType = data[payloadOffset];
        const icmpCode = data[payloadOffset + 1];
        let typeName = "Unknown";
        if (icmpType === 8) typeName = "Echo (ping) Request";
        else if (icmpType === 0) typeName = "Echo (ping) Reply";
        else if (icmpType === 3) typeName = "Destination Unreachable";
        else if (icmpType === 11) typeName = "Time Exceeded";
        
        parsedFields.icmp = {
          "Type": `${icmpType} (${typeName})`,
          "Code": icmpCode
        };
        info = `ICMP ${typeName}`;
      }
    }
  } else if (etherType === 0x0806) { // ARP
    protocol = "ARP";
    protoStack.push("ARP");
    if (data.length < 14 + 28) return null;
    
    const op = (data[20] << 8) | data[21];
    const sha = formatMac(data.subarray(22, 28));
    const spa = `${data[28]}.${data[29]}.${data[30]}.${data[31]}`;
    const tha = formatMac(data.subarray(32, 38));
    const tpa = `${data[38]}.${data[39]}.${data[40]}.${data[41]}`;
    
    parsedFields.arp = {
      "Operation": op === 1 ? "1 (Request)" : op === 2 ? "2 (Reply)" : op + " (Unknown)",
      "Sender MAC": sha,
      "Sender IP": spa,
      "Target MAC": tha,
      "Target IP": tpa
    };
    
    if (op === 1) {
      info = `Who has ${tpa}? Tell ${spa}`;
    } else if (op === 2) {
      info = `${spa} is at ${sha}`;
    } else {
      info = "ARP Control Op " + op;
    }
    
    srcIp = spa;
    dstIp = tpa;
  }
  
  // Format human timestamp
  const date = new Date(tsSec * 1000);
  const timeStr = date.toISOString().split("T")[1].replace("Z", "") + 
                  "." + tsUsec.toString().padStart(6, "0").substring(0, 3);
  
  return {
    id,
    timestamp: timeStr,
    timestampRaw: tsSec + (tsUsec / 1000000),
    srcMac,
    dstMac,
    srcIp,
    dstIp,
    protocol,
    length: data.length,
    info,
    payload: payloadBytes,
    protoStack,
    parsedFields,
    rawData: data
  };
}

function formatMac(arr) {
  return Array.from(arr).map(b => b.toString(16).padStart(2, "0")).join(":");
}

function bytesToAscii(arr) {
  let str = "";
  for (let i = 0; i < arr.length; i++) {
    const c = arr[i];
    if (c >= 32 && c <= 126) {
      str += String.fromCharCode(c);
    } else if (c === 10 || c === 13) {
      str += String.fromCharCode(c);
    } else {
      str += ".";
    }
  }
  return str;
}

function parseDnsPayload(bytes) {
  if (bytes.length < 12) return null;
  const id = (bytes[0] << 8) | bytes[1];
  const qr = (bytes[2] >> 7) & 0x01;
  const qdcount = (bytes[4] << 8) | bytes[5];
  
  if (qdcount === 0) return null;
  
  let offset = 12;
  let parts = [];
  while (offset < bytes.length) {
    const len = bytes[offset];
    if (len === 0) {
      offset++;
      break;
    }
    if (offset + 1 + len > bytes.length) break;
    let label = "";
    for (let i = 0; i < len; i++) {
      label += String.fromCharCode(bytes[offset + 1 + i]);
    }
    parts.push(label);
    offset += 1 + len;
  }
  
  const queryName = parts.join(".");
  if (offset + 4 > bytes.length) return null;
  const qtype = (bytes[offset] << 8) | bytes[offset + 1];
  
  const typeMap = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA"
  };
  
  return {
    transactionId: "0x" + id.toString(16).padStart(4, "0"),
    direction: qr === 0 ? "Query" : "Response",
    queryName,
    queryType: typeMap[qtype] || "Type-" + qtype
  };
}
