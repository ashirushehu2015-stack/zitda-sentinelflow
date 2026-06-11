# ZITDA SentinelFlow: User & Forensic Auditor Manual
**System Version: 1.0.0**  
**Zamfara State ICT Regulatory Agency (ZITDA)**

This manual guides security operators, forensics analysts, and regulatory auditors through the standard operating procedures of the **ZITDA SentinelFlow** traffic forensics console. It details every step from initial authentication to final report printing and data extraction.

---

## Table of Contents
1. [Portal Authentication & Login](#step-1-portal-authentication--login)
2. [Data Ingestion (Importing Capture Files)](#step-2-data-ingestion-importing-capture-files)
3. [Dashboard Analytics Overview](#step-3-dashboard-analytics-overview)
4. [Forensic Examination & DPI](#step-4-forensic-examination--dpi)
5. [Incident Triaging (Alerts Board)](#step-5-incident-triaging-alerts-board)
6. [Compliance Report Compiling & Printing](#step-6-compliance-report-compiling--printing)
7. [Structured Data Exporting](#step-7-structured-data-exporting)
8. [Session Termination (Logout)](#step-8-session-termination-logout)

---

## Step 1: Portal Authentication & Login

To enter the console, users must authenticate using pre-authorized operator profiles.

```
       +---------------------------------------------+
       |             ZITDA SentinelFlow              |
       |               Operator Login                |
       +---------------------------------------------+
       | Username: [ lead.auditor@zitda.gov.ng     ] |
       | PIN:      [ ****************              ] |
       +---------------------------------------------+
       |            [ Authenticate & Enter ]         |
       +---------------------------------------------+
```

1. Navigate to the application URL (Local: `http://localhost:5173`).
2. Input one of the following official credential sets into the form:
   * **Lead Forensics Auditor:**
     * **Username:** `lead.auditor@zitda.gov.ng`
     * **Access PIN:** `LeadAuditor2026!`
   * **Security Operations Analyst:**
     * **Username:** `analyst@zitda.gov.ng`
     * **Access PIN:** `ZitdaAdmin2026!`
   * **External Compliance Auditor:**
     * **Username:** `federal.compliance@nitda.gov.ng`
     * **Access PIN:** `FederalAudit2026!`
3. Click the gold **"Authenticate & Enter Portal"** button.
4. The system will display a loading notice: *"Decrypting Operator Profile & Syncing Audit Logs..."*. Authentication completes in 1.3 seconds, and the main workspace is displayed.

---

## Step 2: Data Ingestion (Importing Capture Files)

Once logged in, the console requires network data to start auditing. The console supports **three ingestion methods** in the top actions panel of the **Dashboard** tab:

```
+-------------------------------------------------------------------------+
| [Drag & Drop Zone]                                                      |
| Drag & Drop Server PCAP capture or JSON session log here, or browse files |
+-------------------------------------------------------------------------+
| [Load ZITDA Cloud Demo Capture Button]                                  |
+-------------------------------------------------------------------------+
```

### Option A: Drag & Drop Ingestion
1. Drag a binary packet capture file (`.pcap`) or a previously exported session log file (`.json`) from your local file manager.
2. Drop it onto the dashed **Upload Zone** box.
3. The uploader will automatically process the file.

### Option B: File Browser Ingestion
1. Click anywhere inside the dashed **Upload Zone** box.
2. The file explorer window will open. Select a `.pcap` or `.json` file and click **Open**.

### Option C: ZITDA Demo Capture Ingestion (Quick Test)
1. Click the gold button: **"Load ZITDA Cloud Demo Capture"**.
2. The system will generate a pre-compiled binary `.pcap` containing 8 diverse cyber threat scenarios targeting state subdomains.

*Note: Once loaded, the filename and file size appear in the green **"Loaded:"** detail panel, and the data export options slide into view.*

---

## Step 3: Dashboard Analytics Overview

Once data is loaded, the dashboard acts as the command center, displaying statistical summaries and interactive charts:

```
+-------------------------------------------------------------------------+
| METRICS CARDS:                                                          |
| [Total Packets: 58]   [Total Volume: 45 KB]   [Alerts: 8]   [Score: 40%] |
+-------------------------------------------------------------------------+
```

1. **Metrics Cards:**
   * **Total Packets:** The absolute number of packets parsed in the file.
   * **Total Volume:** The sum of all packet byte sizes (formatted as Bytes/KB/MB).
   * **Security Alerts:** The total number of alerts triggered.
   * **ZITDA Security Score:** A dynamic security compliance rating (starts at 100%, drops by 15% for each *Critical* threat and 5% for each *Warning* threat).
2. **Interactive Chart Grid:**
   * **Protocol Distribution:** Displays the percentage breakdown of active protocols (e.g. TCP, DNS, SSH, cPanel).
   * **Bandwidth Consumption:** Shows bandwidth usage across government department subdomains.
   * **Traffic Rate:** A timeline graph showing packet flow rate.
   * **Threat Categories:** A polar area chart displaying the frequency of alert types.

---

## Step 4: Forensic Examination & DPI

For low-level packet forensics, switch to the **Forensic Examiner** tab.

```
+-----------------------------------------------------------------------+
|  SEARCH & FILTERS PANEL:                                              |
|  [Search IP...] [Protocol: TCP] [MDA: Finance] [Severity: Critical]    |
+-----------------------------------------------------------------------+
|  PACKET TABLE LIST (Scrollable & Paginated):                          |
|  No. | Timestamp | Src IP | Dst IP | Protocol | Length | Info | Status |
+-----------------------------------------------------------------------+
|  INSPECTORS SPLIT WINDOW:                                             |
|  [ DPI Hierarchical Tree ]          |  [ Raw Hex & ASCII Dump View ]  |
+-----------------------------------------------------------------------+
```

1. **Filtering the Log:**
   * Use the **Search IP or keyword** input to isolate specific source/destination IPs or payload keywords.
   * Dropdowns allow you to filter by specific **Protocols**, target **MDA domains** (e.g., `judiciary.zm.gov.ng`), or **Severity levels**.
   * Click **Reset** to clear all active filters.
2. **Browsing the Packet Table:**
   * Packets are displayed in chronological order (20 per page). Use the **Prev** and **Next** buttons at the bottom of the table to paginate.
   * Threat packets are color-coded with red (Critical) or yellow (Warning) badges.
3. **Deep Packet Inspection (DPI):**
   * Select any packet row in the table.
   * The **Decoded Protocol Fields (DPI)** panel displays a hierarchical tree. Expand nodes (e.g. Ethernet II, IPv4, TCP, DNS) to inspect individual byte header fields (ports, sequence numbers, flags, TTLs, query names).
4. **Hex & ASCII Dump View:**
   * The right-hand inspector shows the raw, unparsed packet bytes in hexadecimal columns alongside printable ASCII characters. Non-printable characters are represented by dots (`.`).

---

## Step 5: Incident Triaging (Alerts Board)

The **Alert Board** displays all security threats flagged by the detection engine.

```
+-------------------------------------------------------------------------+
| [!] CRITICAL: SQL Injection Web Exploit Attempt                         |
| Target MDA: finance.zm.gov.ng | Source: 198.51.100.55 | Packet ID: #23  |
| Description: Web traffic contains SQL strings ...                       |
| [Jump to Packet #23]                                                    |
| ZITDA Policy Mitigation Recommendation: Enable WAF rule signatures...    |
+-------------------------------------------------------------------------+
```

1. Select the **Alert Board** tab (note the red notification badge indicating the active alert count).
2. Browse the alerts list. Each card displays:
   * **Severity Level** (Critical / Warning) and **Category**.
   * **Metadata:** Target MDA, Source IP, Timestamp, and originating Packet ID.
   * **Detailed Description:** Explaining the threat vector detected.
   * **Mitigation Directive:** Concrete steps to remediate the issue based on ZITDA policies.
3. **Investigating the Source Packet:**
   * Click the blue link: **`[Jump to Packet #X]`** on any alert card.
   * The interface will automatically switch to the **Forensic Examiner** tab, navigate to the packet's page, select the packet row, and highlight it in the inspectors.

---

## Step 6: Compliance Report Compiling & Printing

At the end of the audit, navigate to the **Compliance Reports** tab to compile the findings into a formal report:

```
+-------------------------------------------------------------------------+
| 1. Fill out: Lead Auditor Name, Case Reference ID, and Audit Scope Notes.|
| 2. Click [Print ZITDA Regulatory Report]                                |
| 3. System prints A4 formatted audit report PDF.                         |
+-------------------------------------------------------------------------+
```

1. Fill out the report metadata form:
   * **Investigator / Lead Auditor** (defaults to the authenticated operator's role).
   * **Case Reference ID** (default: `ZITDA-CPANEL-2026-001`).
   * **Audit Notes / Summary:** Enter your administrative notes describing the scope and conclusions of the investigation.
2. Click the gold button: **"Print ZITDA Regulatory Report"**.
3. The system print dialog will open.
4. **Export to PDF:** In the printer settings, select **"Save as PDF"** or **"Microsoft Print to PDF"**. Ensure page layouts are set to **Portrait** and click **Save**. The print stylesheet will automatically format the layout into a clean A4 PDF report, hiding all interactive dashboard menus and buttons.

---

## Step 7: Structured Data Exporting

For programmatic review, spreadsheet modeling, or feeding other security systems, use the export actions in the top actions panel on the **Dashboard** tab:

* **Exporting Security Alerts (JSON):**
  * Click the **"Export Alerts (JSON)"** button.
  * A file named `zitda_alerts_export_[timestamp].json` will download. This file contains the complete list of alert structures, perfect for feeding into external SIEM databases or security alert systems.
* **Exporting Packet Capture Catalog (CSV):**
  * Click the **"Export Packets (CSV)"** button.
  * A file named `zitda_packets_export_[timestamp].csv` will download. This file contains the complete packet table list (IDs, timestamps, IPs, protocols, lengths, info summaries, threat status) and can be opened directly in **Microsoft Excel** or **Google Sheets** for further analysis.

---

## Step 8: Session Termination (Logout)

When the forensics session is complete, click **Log Out** in the top-right header:
1. This clears all active arrays (`allPackets`, `filteredPackets`, `allAlerts`) from browser memory.
2. Resets metrics counters to zero.
3. Returns the console to the secure landing portal, ensuring no sensitive data remains in the browser cache.
