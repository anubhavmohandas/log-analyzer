<div align="center">

# 🛡️ CyberNyx Security Log Analyzer

### Advanced threat intelligence and log analysis platform

[![Live Demo](https://img.shields.io/badge/🌐_Live-Launch_App-4CAF50?style=for-the-badge)](https://nyxine-log-analyzer.netlify.app/)
[![GitHub](https://img.shields.io/badge/GitHub-Source-181717?style=for-the-badge&logo=github)](https://github.com/anubhavmohandas/log-analyzer)

**Detect threats faster • Analyze smarter • Stay secure**

![Divider](https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif)

</div>

## ✨ Features

<table>
<tr>
<td width="50%">

### 🎯 Core Capabilities
- ✅ Smart log categorization (12+ types)
- ✅ Real-time threat detection
- ✅ Real IP geolocation (ipapi.co) — no fabricated data, ever
- ✅ IPv4 + IPv6 extraction
- ✅ Advanced pattern matching
- ✅ Brute force detection
- ✅ DDoS identification

</td>
<td width="50%">

### 📊 Visualizations
- ✅ Interactive pie charts
- ✅ Severity-composition timeline (not just volume)
- ✅ Correlation graph (actor ↔ IP ↔ endpoint ↔ MITRE)
- ✅ Top IPs dashboard, sorted by real risk
- ✅ Category breakdown, sorted by risk-weighted severity
- ✅ Real-time statistics
- ✅ Dark/Light mode

</td>
</tr>
<tr>
<td width="50%">

### 🔧 Analysis Tools
- ✅ Multi-level filtering
- ✅ Full-text search
- ✅ Bookmark system
- ✅ CSV-aware column parsing (auto-detected)
- ✅ Multi-line log entry merging (stack traces, wrapped JSON)
- ✅ Chunked processing — large files won't freeze the tab
- ✅ Export to CSV/JSON

</td>
<td width="50%">

### 🛡️ Security Detection
- ✅ Port scanning
- ✅ Failed login tracking
- ✅ Resource exhaustion
- ✅ Data exfiltration
- ✅ Access control violations
- ✅ Config change monitoring

</td>
</tr>
<tr>
<td width="50%">

### 🕵️ Investigation Engine
- ✅ Session-based correlation (per user/IP)
- ✅ Risk scoring (0–100) with a visible, real breakdown of what earned the score
- ✅ MITRE ATT&CK technique mapping, click-to-filter
- ✅ Auto-generated analyst case summaries
- ✅ Expandable investigation timelines with source IP / last seen / duration
- ✅ "Why flagged?" + linked-session context on every event
- ✅ Copy-to-clipboard IOCs (users, IPs)

</td>
<td width="50%">

### 📄 Reporting
- ✅ One-click auto-generated HTML report
- ✅ Analyst Conclusion / verdict section (confirmed vs. unconfirmed, explicitly)
- ✅ Case ID, engine version, MITRE coverage, SHA-256 log integrity hash
- ✅ Recommendations grouped by priority (Immediate / 24h / Routine)
- ✅ Affected-users table with risk, last seen, MITRE technique
- ✅ Self-contained, shareable output file

</td>
</tr>
</table>

---

## 🚀 Quick Start

### Prerequisites
```bash
Node.js 18+ required
npm 9+ required
```

### Installation

```bash
# Clone repository
git clone https://github.com/anubhavmohandas/log-analyzer.git
cd log-analyzer

# Install dependencies
npm install

# Run development server
npm run dev

# Build for production
npm run build
```

---

## 📋 Supported Log Types

| Type | Examples | Status |
|------|----------|--------|
| 🛡️ **Firewalls** | NetScreen, Cisco ASA, pfSense | ✅ |
| 🌐 **Network** | Cisco IOS, Juniper, HP | ✅ |
| 💻 **Systems** | Linux syslog, Windows Event | ✅ |
| 🌍 **Web Servers** | Apache, Nginx, IIS | ✅ |
| 🔐 **Auth** | SSH, RDP, VPN, LDAP | ✅ |

---

## 💻 Usage

### 1. Upload Log File
- Supports `.txt`, `.log`, `.csv` formats
- Or try pre-loaded samples

### 2. View Analysis
- Automatic threat detection
- Real IP geolocation (looked up live via [ipapi.co](https://ipapi.co) — private/internal IPs resolve instantly with no network call; public IPs show "Looking up…" then real data, or an explicit "unavailable" if the lookup fails or is rate-limited)
- Interactive charts and stats

### 3. Filter & Search
- Filter by category or severity
- Full-text search across logs
- Bookmark important events

### 4. Investigate
- Review correlated sessions per user/IP with a 0–100 risk score
- Drill into MITRE ATT&CK-mapped findings and chronological event timelines
- Read auto-generated case summaries for each session

### 5. Export Results
- CSV / JSON export for further processing
- One-click self-contained HTML security report (executive summary + MITRE references + event appendix)

---

## 🛠️ Tech Stack

![React](https://img.shields.io/badge/React-19.2-61DAFB?style=for-the-badge&logo=react&logoColor=black)
![Vite](https://img.shields.io/badge/Vite-7.x-646CFF?style=for-the-badge&logo=vite&logoColor=white)
![Tailwind](https://img.shields.io/badge/Tailwind-4.1-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white)
![Recharts](https://img.shields.io/badge/Recharts-3.4-8884d8?style=for-the-badge)

**Dependencies:**
- `react` - UI framework
- `lucide-react` - Icons
- `recharts` - Charts & graphs
- `tailwindcss` - Styling

---

## 📊 Event Categories

<div align="center">

| 🔐 Login Attempts | 🚨 Security Alerts | 🛡️ Firewall Actions | 🌐 Network Changes |
|-------------------|--------------------|-----------------------|--------------------|
| 🔒 Access Control | 💻 System Events | ⚙️ Config Changes | 📡 Data Transfer |
| 🔌 Port Activity | 🔗 Sessions | ⚡ Resource Alerts | ❌ Error Events |

</div>

---

## 🔍 Example Output

```
🚨 THREAT DETECTED: Brute Force Attack

Severity: CRITICAL
3 failed login attempts from IP: 198.51.100.75

💡 Recommendation:
Block IP immediately. Enable rate limiting. Implement 2FA.

🌍 IP Intelligence (live lookup via ipapi.co):
Country: United States  |  City: Ashburn  |  ISP: Amazon AWS

⚠️ Status: Elevated — derived from this analysis (2 alerts, 1 investigation session),
not from geolocation. Location and risk are always shown separately.
```

---

## 🕵️ Investigation & Reporting

Events are correlated into sessions per user or IP and scored 0–100 based on severity, technique diversity, and behavioral patterns — and every score shows its real breakdown (e.g. *"62 (base) + 15 (3 extra failures) + 8 (followed by successful login) = 85"*), not just a bare number. High-scoring sessions are mapped to **MITRE ATT&CK** techniques (e.g. `T1078` Valid Accounts, `T1046` Network Service Discovery, `T1595` Active Scanning) with tactic labels, click-to-filter, and direct links to the ATT&CK reference.

Each investigation session includes an auto-generated case summary, source IP / last-seen / duration, and an expandable chronological timeline of the underlying events — built for analysts who need context, not just a raw log line. A **Correlation Graph** shows actors, source IPs, endpoints, and MITRE techniques as a clickable node graph, built from the same session data, so shared infrastructure between different accounts is visible instead of buried across separate rows.

The **Generate Report** action produces a self-contained HTML file with an Analyst Conclusion (explicitly stating whether there's confirmed compromise or just unconfirmed suspicious behavior), a case ID and SHA-256 hash of the analyzed log for integrity tracking, MITRE coverage, recommendations grouped by urgency, and a filtered event appendix (Medium severity and above).

### Known limitations (stated plainly, not buried)
- **Geolocation** depends on a free third-party API (ipapi.co) with a daily rate limit. Under heavy use, lookups may show "rate-limited" instead of resolving — this is intentional; the analyzer never falls back to guessed data.
- **Multi-line log merging** and **CSV column detection** are heuristic. Unusual formats may need manual review of the parsed output.
- Detection rules cover **7 MITRE ATT&CK techniques**; the "MITRE coverage" figure in reports is honest about this ceiling, not a claim of full ATT&CK coverage.
- This is a client-side, rule-based analyzer — not a SIEM. Treat findings as investigative leads, not a substitute for a qualified analyst.

---

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

Report bugs or suggest features via [GitHub Issues](https://github.com/anubhavmohandas/log-analyzer/issues).

---

## 📄 License

MIT License - Free to use and modify.

---

## 👨‍💻 Author

**Anubhav Mohandas**

[![GitHub](https://img.shields.io/badge/GitHub-anubhavmohandas-181717?style=for-the-badge&logo=github)](https://github.com/anubhavmohandas)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0077B5?style=for-the-badge&logo=linkedin)](https://linkedin.com/in/anubhavmohandas)

---

<div align="center">

### 🎉 Ready to Start?

[![Launch App](https://img.shields.io/badge/🚀_Launch_Now-Click_Here-FF6B6B?style=for-the-badge)](https://nyxine-log-analyzer.netlify.app/)

![Divider](https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif)

**Built with ❤️ by Anubhav Mohandas**

*Cybersecurity Portfolio Project*

</div>
