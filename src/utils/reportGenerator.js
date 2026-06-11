// ZITDA SentinelFlow Forensic Report Generator

/**
 * Compiles parsed packets and threat alerts into a print-friendly regulatory report template.
 * @param {Array[]} packets 
 * @param {Array[]} alerts 
 * @param {Object} metadata Form parameters (investigator, caseId, notes)
 * @returns {string} Formatted HTML string.
 */
export function compileForensicReport(packets, alerts, metadata) {
  const totalPackets = packets.length;
  const totalVolumeBytes = packets.reduce((acc, p) => acc + p.length, 0);
  const totalVolume = formatVolume(totalVolumeBytes);
  const criticalCount = alerts.filter(a => a.severity === 'CRITICAL').length;
  const warningCount = alerts.filter(a => a.severity === 'WARNING').length;
  const currentDate = new Date().toLocaleString();
  
  // Calculate compliance score (base 100%, deduct 15% per critical, 5% per warning, min 10%)
  const rawScore = 100 - (criticalCount * 15) - (warningCount * 5);
  const securityScore = Math.max(10, rawScore) + "%";

  // Build Alert logs list
  let threatLogsHtml = '';
  if (alerts.length === 0) {
    threatLogsHtml = `
      <div style="border: 1px solid #10b981; background: #ecfdf5; padding: 1rem; border-radius: 4px; color: #065f46; font-size: 0.85rem; margin-top: 10px;">
        <strong>✔ System Compliant:</strong> No critical anomalies or administrative policy violations were detected in this packet stream.
      </div>
    `;
  } else {
    alerts.forEach((alert, idx) => {
      const severityColor = alert.severity === 'CRITICAL' ? '#ef4444' : '#f59e0b';
      const severityLabel = alert.severity === 'CRITICAL' ? 'CRITICAL THREAT' : 'SECURITY WARNING';
      
      threatLogsHtml += `
        <div style="border: 1px solid #ddd; border-left: 5px solid ${severityColor}; padding: 1.2rem; margin-bottom: 1.2rem; page-break-inside: avoid; background-color: #fafafa; border-radius: 4px;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; font-family: sans-serif;">
            <strong style="font-size: 1rem; color: #111;">[Finding #${idx + 1}] ${alert.title}</strong>
            <span style="font-size: 0.75rem; font-weight: 700; color: #fff; background-color: ${severityColor}; padding: 0.25rem 0.5rem; border-radius: 3px; text-transform: uppercase;">
              ${severityLabel}
            </span>
          </div>
          <table style="width: 100%; border-collapse: collapse; margin-bottom: 0.75rem; font-size: 0.8rem; font-family: monospace; color: #444;">
            <tr>
              <td style="width: 15%; font-weight: bold; padding: 2px 0;">Affected MDA:</td>
              <td style="width: 35%; padding: 2px 0;">${alert.mda}</td>
              <td style="width: 15%; font-weight: bold; padding: 2px 0;">Source IP:</td>
              <td style="width: 35%; padding: 2px 0;">${alert.source}</td>
            </tr>
            <tr>
              <td style="font-weight: bold; padding: 2px 0;">Timestamp:</td>
              <td style="padding: 2px 0;">${alert.timestamp}</td>
              <td style="font-weight: bold; padding: 2px 0;">Destination:</td>
              <td style="padding: 2px 0;">${alert.destination}</td>
            </tr>
            <tr>
              <td style="font-weight: bold; padding: 2px 0;">Category:</td>
              <td style="padding: 2px 0;">${alert.category}</td>
              <td style="font-weight: bold; padding: 2px 0;">Packet ID:</td>
              <td style="padding: 2px 0;">#${alert.packetId}</td>
            </tr>
          </table>
          <p style="font-size: 0.85rem; line-height: 1.5; color: #222; margin-bottom: 0.75rem; font-family: sans-serif;">
            <strong>Forensic Analysis:</strong> ${alert.description}
          </p>
          <div style="background-color: #fef3c7; border: 1px solid #fcd34d; padding: 0.75rem; border-radius: 3px; font-size: 0.8rem; color: #92400e; font-family: sans-serif;">
            <strong style="display:block; margin-bottom: 2px; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: #78350f;">
              ZITDA Regulatory Action Directive
            </strong>
            ${alert.recommendation}
          </div>
        </div>
      `;
    });
  }

  return `
    <div style="font-family: Arial, sans-serif; color: #111; max-width: 800px; margin: 0 auto; line-height: 1.4; padding: 10px;">
      
      <!-- ZITDA Header -->
      <div style="border-bottom: 3px solid #10b981; padding-bottom: 1rem; margin-bottom: 1.5rem; display: flex; justify-content: space-between; align-items: center;">
        <div>
          <span style="font-size: 0.75rem; font-weight: bold; color: #10b981; letter-spacing: 0.1em; text-transform: uppercase; font-family: sans-serif;">
            Zamfara State Government, Nigeria
          </span>
          <h1 style="font-size: 1.6rem; font-weight: bold; margin: 2px 0; color: #000; font-family: sans-serif;">
            Zamfara State Information Technology Development Agency (ZITDA)
          </h1>
          <p style="font-size: 0.9rem; margin: 0; color: #555; font-family: sans-serif;">
            Regulatory Audit & Cloud Security Compliance Branch
          </p>
        </div>
        <div style="width: 54px; height: 54px; background: linear-gradient(135deg, #10b981, #f59e0b); border-radius: 8px; display: flex; align-items: center; justify-content: center; font-weight: bold; color: #000; font-size: 1.5rem; font-family: sans-serif; flex-shrink: 0;">
          Z
        </div>
      </div>

      <!-- Report Metadata -->
      <div style="margin-bottom: 1.5rem; border: 1px solid #ddd; padding: 1rem; border-radius: 4px; background-color: #fafafa;">
        <h2 style="font-size: 1.1rem; margin-top: 0; margin-bottom: 0.75rem; border-bottom: 1px solid #eee; padding-bottom: 0.25rem; font-family: sans-serif;">
          Forensic Audit Reference Card
        </h2>
        <table style="width: 100%; border-collapse: collapse; font-size: 0.85rem; font-family: sans-serif;">
          <tr>
            <td style="width: 25%; font-weight: bold; padding: 4px 0;">Case ID:</td>
            <td style="width: 25%; padding: 4px 0;">${metadata.caseId || 'N/A'}</td>
            <td style="width: 25%; font-weight: bold; padding: 4px 0;">Audit Date/Time:</td>
            <td style="width: 25%; padding: 4px 0;">${currentDate}</td>
          </tr>
          <tr>
            <td style="font-weight: bold; padding: 4px 0;">Lead Auditor:</td>
            <td style="padding: 4px 0;">${metadata.investigator || 'N/A'}</td>
            <td style="font-weight: bold; padding: 4px 0;">Infrastructure Scope:</td>
            <td style="padding: 4px 0;">State MDA cPanel Cloud Host</td>
          </tr>
        </table>
      </div>

      <!-- Executive Traffic Summary -->
      <div style="margin-bottom: 1.5rem; font-family: sans-serif;">
        <h2 style="font-size: 1.1rem; margin-bottom: 0.5rem; color: #000;">1. Executive Traffic Summary</h2>
        <p style="font-size: 0.85rem; color: #333; line-height: 1.5;">
          This forensic capture report details traffic analyzed on Zamfara State government cloud assets. Under ZITDA Regulatory Policy (Cloud Administration, 2026), all government ministries must maintain audit trails of cPanel and administrative access. 
        </p>
        <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-top: 10px; text-align: center;">
          <div style="border: 1px solid #ddd; padding: 0.5rem; border-radius: 4px;">
            <div style="font-size: 0.75rem; color: #666; text-transform: uppercase;">Packets Audited</div>
            <strong style="font-size: 1.1rem; font-family: monospace;">${totalPackets}</strong>
          </div>
          <div style="border: 1px solid #ddd; padding: 0.5rem; border-radius: 4px;">
            <div style="font-size: 0.75rem; color: #666; text-transform: uppercase;">Traffic Volume</div>
            <strong style="font-size: 1.1rem; font-family: monospace;">${totalVolume}</strong>
          </div>
          <div style="border: 1px solid #ddd; padding: 0.5rem; border-radius: 4px;">
            <div style="font-size: 0.75rem; color: #666; text-transform: uppercase;">Security Alerts</div>
            <strong style="font-size: 1.1rem; font-family: monospace; color: ${alerts.length > 0 ? '#ef4444' : '#10b981'};">${alerts.length}</strong>
          </div>
          <div style="border: 1px solid #ddd; padding: 0.5rem; border-radius: 4px;">
            <div style="font-size: 0.75rem; color: #666; text-transform: uppercase;">Compliance Score</div>
            <strong style="font-size: 1.1rem; font-family: monospace; color: ${rawScore >= 80 ? '#10b981' : rawScore >= 50 ? '#f59e0b' : '#ef4444'};">${securityScore}</strong>
          </div>
        </div>
      </div>

      <!-- Investigator Notes -->
      <div style="margin-bottom: 1.5rem; font-family: sans-serif;">
        <h2 style="font-size: 1.1rem; margin-bottom: 0.5rem; color: #000;">2. Scope of Audit &amp; Investigator Notes</h2>
        <div style="border: 1px solid #ddd; padding: 0.75rem; border-radius: 4px; min-height: 50px; font-size: 0.85rem; color: #333; background-color: #fafafa;">
          ${metadata.notes ? metadata.notes.replace(/\n/g, '<br>') : 'Forensic packet dump analysis of cPanel services. Targeted monitoring of governmental MDA subdomains to verify secure admin channels, detect SQL injection patterns, SSH brute forcing, and mail server relayer configurations.'}
        </div>
      </div>

      <!-- Detailed Findings Logs -->
      <div style="margin-bottom: 2rem; font-family: sans-serif;">
        <h2 style="font-size: 1.1rem; margin-bottom: 0.75rem; color: #000;">3. Regulatory Vulnerability &amp; Threat Logs</h2>
        ${threatLogsHtml}
      </div>

      <!-- Signature Blocks -->
      <div style="margin-top: 4rem; display: flex; justify-content: space-between; page-break-inside: avoid; font-family: sans-serif;">
        <div style="width: 45%; border-top: 1.5px solid #111; text-align: center; padding-top: 0.5rem; font-size: 0.85rem;">
          <strong>Lead Forensics Auditor Signature</strong>
          <div style="color: #666; font-size: 0.75rem; margin-top: 2px;">ZITDA Audit & Security Operations</div>
        </div>
        <div style="width: 45%; border-top: 1.5px solid #111; text-align: center; padding-top: 0.5rem; font-size: 0.85rem;">
          <strong>ZITDA Director of Cyber Operations</strong>
          <div style="color: #666; font-size: 0.75rem; margin-top: 2px;">Director Sign-off & Regulatory Seal</div>
        </div>
      </div>

    </div>
  `;
}

function formatVolume(bytes) {
  if (bytes >= 1048576) return (bytes / 1048576).toFixed(2) + " MB";
  if (bytes >= 1024) return (bytes / 1024).toFixed(2) + " KB";
  return bytes + " Bytes";
}
