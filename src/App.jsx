import React, { useState, useRef } from 'react';
import { Shield, AlertTriangle, FileText, Upload, Search, Filter, Download, Activity, Clock, Globe, BookmarkPlus, ChevronDown, ChevronUp, MapPin, Eye, EyeOff } from 'lucide-react';
import { LineChart, Line, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const LogAnalyzer = () => {
  const [uploadedFile, setUploadedFile] = useState(null);
  const [analysis, setAnalysis] = useState(null);
  const [filterCategory, setFilterCategory] = useState('all');
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [bookmarkedEvents, setBookmarkedEvents] = useState(new Set());
  const [expandedEvent, setExpandedEvent] = useState(null);
  const [showCharts, setShowCharts] = useState(true);
  const [showInvestigation, setShowInvestigation] = useState(true);
  const [expandedSessions, setExpandedSessions] = useState(new Set()); // empty = all collapsed by default
  const [showAllSessions, setShowAllSessions] = useState(false);
  const [showSuspiciousOnly, setShowSuspiciousOnly] = useState(true);
  const [darkMode, setDarkMode] = useState(true);
  const [inputMode, setInputMode] = useState('upload');
  const [logText, setLogText] = useState('');
  const fileInputRef = useRef(null);

  const sampleLogs = {
    firewall: `Jun 1 22:01:35 [xx] ns5gt: NetScreen device_id=ns5gt [Root]system-alert-00016: Port scan! From 203.0.113.45:54886 to 192.168.1.100:406, proto TCP (zone Untrust, int untrust). Occurred 1 times. (2004-06-01 22:09:03)
Jun 1 22:01:57 [xx] ns5gt: NetScreen device_id=ns5gt [Root]system-alert-00016: Port scan! From 203.0.113.45:55181 to 192.168.1.100:1358, proto TCP (zone Untrust, int untrust). Occurred 1 times. (2004-06-01 22:09:25)
Jun 2 11:24:16 fire00 sav00: NetScreen device_id=sav00 [Root]system-critical-00436: Large ICMP packet! From 203.0.113.45 to 192.168.1.100, proto 1 (zone Untrust, int ethernet1/2). Occurred 1 times. (2006-06-02 11:24:16)
Jun 1 22:02:12 [xx] ns5gt: NetScreen device_id=ns5gt [Root]system-notification-00002: Admin user "admin" logged in for Web(http) management (port 8080) from 10.0.0.50:2150 (2004-06-01 22:09:40)
Jun 2 14:55:46 fire00 fire00: NetScreen device_id=fire00 [Root]system-notification-00257(traffic): start_time="2006-06-02 14:55:45" duration=0 policy_id=119 service=udp/port:7001 proto=17 src zone=Trust dst zone=Untrust action=Deny sent=0 rcvd=0 src=192.168.2.1 dst=203.0.113.50 src_port=3036 dst_port=7001`,
    switch: `Mar 26 09:36:43: %LINK-5-CHANGED: Interface Fastethernet0/0, changed state to administratively down
Mar 26 09:40:21: %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/1, changed state to up
Mar 26 09:42:15: %SYS-5-CONFIG_I: Configured from console by admin
Mar 26 10:15:33: %SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: admin] [Source: 10.1.1.50] at 10:15:33 UTC
Mar 26 10:20:45: %SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: root] [Source: 198.51.100.75] [localport: 22] at 10:20:45 UTC
Mar 26 10:21:10: %SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: root] [Source: 198.51.100.75] [localport: 22] at 10:21:10 UTC
Mar 26 10:21:35: %SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: admin] [Source: 198.51.100.75] [localport: 22] at 10:21:35 UTC`,
    webaccess: `2024-03-15 08:55:10 INFO user=Zm3aLpW9jK src=10.2.3.44 GET /auth/login - Login Success
2024-03-15 08:55:14 INFO user=Zm3aLpW9jK src=10.2.3.44 GET /dashboard - Dashboard
2024-03-15 08:58:22 INFO user=Zm3aLpW9jK src=10.2.3.44 GET /api/factory/status - Factory Status
2024-03-15 09:02:45 INFO user=Zm3aLpW9jK src=10.2.3.44 GET /api/machine/status - Machine Status API
2024-03-15 09:05:11 INFO user=Zm3aLpW9jK src=10.2.3.44 GET /api/machine/status - Machine Status API
2024-03-15 09:12:33 INFO user=Zm3aLpW9jK src=10.2.3.44 GET /dashboard - Dashboard
2024-03-15 09:18:07 INFO user=Zm3aLpW9jK src=10.2.3.44 GET /reports - Report Access
2024-03-15 09:00:05 INFO user=K7mXnPqR2vB src=192.168.1.102 GET /auth/login - Login Success
2024-03-15 09:00:06 INFO user=K7mXnPqR2vB src=192.168.1.102 GET /dashboard - Dashboard
2024-03-15 09:00:09 INFO user=K7mXnPqR2vB src=192.168.1.102 GET /api/factory/status - Factory Status
2024-03-15 09:00:12 INFO user=K7mXnPqR2vB src=192.168.1.102 GET /api/machine/status - Machine Status API
2024-03-15 09:00:52 INFO user=K7mXnPqR2vB src=192.168.1.102 GET /api/machine/status - Machine Status API
2024-03-15 09:01:32 INFO user=K7mXnPqR2vB src=192.168.1.102 GET /api/machine/status - Machine Status API
2024-03-15 09:02:12 INFO user=K7mXnPqR2vB src=192.168.1.102 GET /api/machine/status - Machine Status API
2024-03-15 09:02:52 INFO user=K7mXnPqR2vB src=192.168.1.102 GET /api/machine/status - Machine Status API
2024-03-15 09:03:32 INFO user=K7mXnPqR2vB src=192.168.1.102 GET /api/machine/status - Machine Status API
2024-03-15 09:04:12 INFO user=K7mXnPqR2vB src=192.168.1.102 GET /api/machine/status - Machine Status API
2024-03-15 09:04:52 INFO user=K7mXnPqR2vB src=192.168.1.102 GET /api/machine/status - Machine Status API
2024-03-15 09:05:32 INFO user=K7mXnPqR2vB src=192.168.1.102 GET /api/machine/status - Machine Status API
2024-03-15 09:06:12 INFO user=K7mXnPqR2vB src=192.168.1.102 GET /api/machine/status - Machine Status API
2024-03-15 10:15:22 WARNING user=BruteForce src=185.220.101.45 GET /auth/login - Login Failed
2024-03-15 10:15:25 WARNING user=BruteForce src=185.220.101.45 GET /auth/login - Login Failed
2024-03-15 10:15:28 WARNING user=BruteForce src=185.220.101.45 GET /auth/login - Login Failed
2024-03-15 10:15:31 WARNING user=BruteForce src=185.220.101.45 GET /auth/login - Login Failed
2024-03-15 10:15:34 WARNING user=BruteForce src=185.220.101.45 GET /auth/login - Login Failed
2024-03-15 10:15:37 WARNING user=BruteForce src=185.220.101.45 GET /auth/login - Login Failed
2024-03-15 10:15:40 WARNING user=BruteForce src=185.220.101.45 GET /auth/login - Login Failed
2024-03-15 10:15:43 WARNING user=BruteForce src=185.220.101.45 GET /auth/login - Login Failed
2024-03-15 10:15:46 WARNING user=BruteForce src=185.220.101.45 GET /auth/login - Login Failed
2024-03-15 10:15:49 WARNING user=BruteForce src=185.220.101.45 GET /auth/login - Login Failed
2024-03-15 10:16:22 INFO user=BruteForce src=185.220.101.45 GET /auth/login - Login Success
2024-03-15 10:16:25 INFO user=BruteForce src=185.220.101.45 GET /dashboard - Dashboard`,
    system: `2024-11-09 10:23:45 INFO: System boot completed
2024-11-09 10:25:12 WARNING: High CPU usage detected - 95%
2024-11-09 10:30:22 ERROR: Failed authentication attempt for user 'administrator' from 198.51.100.100
2024-11-09 10:31:05 ERROR: Failed authentication attempt for user 'admin' from 198.51.100.100
2024-11-09 10:31:48 ERROR: Failed authentication attempt for user 'root' from 198.51.100.100
2024-11-09 10:35:10 INFO: Service 'apache2' started
2024-11-09 10:40:33 CRITICAL: Disk space critical - 98% used on /var
2024-11-09 10:45:22 WARNING: Unusual outbound traffic detected - 500MB in 5 minutes to 203.0.113.200`
  };

  const STATIC_ASSET_RE = /\.(css|js|mjs|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|map|webp|avif|otf|mp4|mp3)(\?[^"'\s]*)?(\s|"|'|$)/i;

  const eventCategories = {
    'Login Attempts': { patterns: [/login.*(success|fail|attempt|denied)|authentication.*(success|fail|error)/i, /failed.*password|invalid.*credentials|auth.*fail|login.*fail/i, /successful.*login|logged in|authentication.*success|login success/i, /\b(ssh|rdp|telnet|ftp)\b.*(login|auth|connect)/i, /\b(401|403)\b.*auth|auth.*\b(401|403)\b/i], icon: '🔐', color: 'blue' },
    'Network Changes': { patterns: [/interface.*up|interface.*down|link.*up|link.*down/i, /route.*add|route.*del|routing.*change/i, /vlan.*config|port.*config|switch.*config/i, /network.*change|topology.*change/i], icon: '🌐', color: 'cyan' },
    'Firewall Actions': { patterns: [/action=(deny|block|drop|reject|permit|allow)/i, /firewall.*rule|acl|access.*list/i, /src=.*dst=|proto=\w+.*src=/i, /\bDeny\b.*\bpolicy\b|\bpermit\b.*\bpolicy\b/i], icon: '🛡️', color: 'purple' },
    'Configuration Changes': { patterns: [/config.*change|configuration|configured from/i, /policy.*change|rule.*change|setting.*change/i, /admin.*config|root.*config/i, /\bmodify\b|\bedit.*config\b/i], icon: '⚙️', color: 'yellow' },
    'System Events': { patterns: [/\b(started|stopped|restarted|rebooted)\b/i, /service.*up|service.*down|daemon\b/i, /system.*error|kernel|crash|panic/i, /\bboot\b.*complet/i], icon: '💻', color: 'green' },
    'Security Alerts': { patterns: [/\b(attack|intrusion|breach|exploit|vulnerability)\b/i, /malware|virus|trojan|backdoor|ransomware/i, /port.*scan|port scan|scan.*detect/i, /\b(ddos|flood)\b/i], icon: '🚨', color: 'red' },
    'Access Control': { patterns: [/access.*denied|forbidden|privilege.*escal/i, /\bunauthorized\b|\bunauthenticated\b/i, /role.*change|group.*add|user.*add/i, /sudo|privilege.*escalat/i], icon: '🔒', color: 'orange' },
    'Data Transfer': { patterns: [/\b(upload|download|file.*transfer|exfil)\b/i, /bytes.*sent|bytes.*received|sent=\d+.*rcvd=\d+/i, /\b(sftp|scp)\b|http.*post.*large/i, /unusual.*traffic|abnormal.*transfer/i], icon: '📡', color: 'indigo' },
    'Port Activity': { patterns: [/port.*scan|port scan|\bsyn.*flood\b/i, /\b(ssh|rdp|telnet)\b.*\b(refused|scan|probe|attempt)\b/i, /dport=\d+|dst_port=\d+|destination.*port.*\d+/i, /connection.*refused.*port|port.*unreachable/i], icon: '🔌', color: 'teal' },
    'Session Management': { patterns: [/session.*(start|end|expire|creat)/i, /connection.*(establish|close|terminat)/i, /\btimeout\b|\bidle\b|\bdisconnect\b/i], icon: '🔗', color: 'pink' },
    'Resource Alerts': { patterns: [/\b(cpu|memory|disk|ram)\b.*(usage|critical|high|\d{2,3}%)/i, /\d{2,3}%.*\b(cpu|memory|disk)\b/i, /\b(overload|exhaustion|threshold)\b/i], icon: '⚡', color: 'amber' },
    'Error Events': { patterns: [/\b(error|fatal|exception|abort|crash|panic)\b/i, /\b(5\d\d)\b.*HTTP|\bHTTP.*\b(5\d\d)\b/i, /corrupt|invalid.*data/i], icon: '❌', color: 'rose' }
  };

  const detectEventType = (logLine) => {
    if (/port.*scan/i.test(logLine)) return 'Port Scan Detected';
    if (/large.*icmp|ping.*flood/i.test(logLine)) return 'Large ICMP Packet (Possible DDoS)';
    if (/logged in/i.test(logLine) && /admin|root/i.test(logLine)) return 'Admin Login';
    if (/login.*success/i.test(logLine)) return 'Successful Login';
    if (/login.*fail/i.test(logLine)) return 'Failed Login Attempt';
    if (/interface.*down/i.test(logLine)) return 'Interface Down';
    if (/interface.*up/i.test(logLine)) return 'Interface Up';
    if (/configured from/i.test(logLine)) return 'Configuration Change';
    if (/action=deny|deny|block|drop/i.test(logLine)) return 'Traffic Denied';
    if (/failed.*authentication/i.test(logLine)) return 'Failed Authentication';
    if (/cpu.*usage|memory|disk.*space/i.test(logLine)) return 'Resource Alert';
    if (/service.*start/i.test(logLine)) return 'Service Started';
    if (/boot.*completed/i.test(logLine)) return 'System Boot';
    if (/unusual.*traffic/i.test(logLine)) return 'Unusual Network Activity';
    if (/machine.*status|\/api\/machine|machine status api/i.test(logLine)) return 'Machine Status API';
    if (/factory.*status|\/api\/factory|factory status/i.test(logLine)) return 'Factory Status API';
    if (/dashboard/i.test(logLine)) return 'Dashboard Access';
    if (/report.*access|\/reports/i.test(logLine)) return 'Report Access';
    if (/\/api\//i.test(logLine)) return 'API Request';
    return 'General Event';
  };

  const categorizeLogEntry = (logLine) => {
    const categories = [];
    Object.entries(eventCategories).forEach(([category, config]) => {
      const hasMatch = config.patterns.some(pattern => pattern.test(logLine));
      if (hasMatch) categories.push(category);
    });
    return categories.length > 0 ? categories : ['Uncategorized'];
  };

  const extractParameters = (logLine) => {
    const params = {};
    const timestampPatterns = [/(\d{2}:\d{2}:\d{2})/, /(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})/, /(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})/, /([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/];
    timestampPatterns.forEach(pattern => { const match = logLine.match(pattern); if (match && !params.timestamp) params.timestamp = match[1]; });
    
    const ipPattern = /(?:src|source|from|client)[=:\s]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(?:^|\s)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?=\s|:)/gi;
    const ips = [...logLine.matchAll(ipPattern)];
    if (ips.length > 0) params.sourceIP = ips[0][1] || ips[0][2];
    
    const dstIpPattern = /(?:dst|destination|to|server)[=:\s]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i;
    const dstMatch = logLine.match(dstIpPattern);
    if (dstMatch) params.destinationIP = dstMatch[1];
    
    const portPattern = /(?:port|sport|dport)[=:\s]+(\d+)/gi;
    const ports = [...logLine.matchAll(portPattern)];
    if (ports.length > 0) params.port = ports[0][1];
    
    const protoPattern = /(?:proto|protocol)[=:\s]+(\w+)/i;
    const protoMatch = logLine.match(protoPattern);
    if (protoMatch) params.protocol = protoMatch[1];
    
    const actionPattern = /(deny|permit|allow|block|drop|accept|reject|fail|success|start|stop)/i;
    const actionMatch = logLine.match(actionPattern);
    if (actionMatch) params.action = actionMatch[1];
    
    const userPattern = /(?:userId|user|username|account)[=:\s"']+([^"'\s\]]+)/i;
    const userMatch = logLine.match(userPattern);
    if (userMatch) params.user = userMatch[1];
    
    const interfacePattern = /(?:interface|int)[:\s]+(\S+)/i;
    const interfaceMatch = logLine.match(interfacePattern);
    if (interfaceMatch) params.interface = interfaceMatch[1];

    // HTTP status code (space-delimited 3-digit code)
    const statusMatch = logLine.match(/\s(2\d\d|3\d\d|4\d\d|5\d\d)\s/);
    if (statusMatch) params.statusCode = statusMatch[1];

    // URL path from HTTP method line
    const urlMatch = logLine.match(/(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+([^\s"]+)/i);
    if (urlMatch) params.url = urlMatch[1];

    return params;
  };

  const assessThreatLevel = (categories, logLine, params) => {
    // Static assets are always informational regardless of other signals
    const url = params.url || '';
    if (STATIC_ASSET_RE.test(url) || STATIC_ASSET_RE.test(logLine)) return 'low';

    const status = params.statusCode || '';
    // 2xx/3xx on non-static paths are low unless other signals fire
    const isSuccessResponse = /^2\d\d$/.test(status) || /^3\d\d$/.test(status);

    // Definite attack language → critical
    if (/\b(attack|breach|exploit|intrusion|ransomware|malware|backdoor|rootkit|ddos)\b/i.test(logLine)) return 'critical';

    // Explicit scan/probe + port activity → high
    if (/\b(port.*scan|port scan|syn.*flood|scan.*detect)\b/i.test(logLine)) return 'high';

    // Brute force / credential spray indicators → high
    if (/\b(brute.?force|credential.*stuff|account.*lock)\b/i.test(logLine)) return 'high';

    const hasSecurityAlert = categories.includes('Security Alerts');
    const hasAccessControl = categories.includes('Access Control');

    // Explicit denial/block from firewall/ACL
    if (categories.includes('Firewall Actions') && /\b(deny|block|drop|reject)\b/i.test(logLine)) return 'medium';

    // 401/403 responses — medium (not high; single 403 is routine)
    if (/^40[13]$/.test(status)) return 'medium';

    // Unauthorized / access denied keywords — but not in static-asset context
    if (/\bunauthorized\b|\baccess denied\b|\bforbidden\b/i.test(logLine)) {
      if (hasSecurityAlert || hasAccessControl) return 'high';
      return 'medium';
    }

    // Login/auth failures — medium (brute force is caught earlier with explicit keyword)
    if (categories.includes('Login Attempts') && /\b(fail|denied|invalid|bad.*password)\b/i.test(logLine)) return 'medium';

    // Critical resource state
    if (categories.includes('Resource Alerts') && /\b(critical|exhausted|overload)\b/i.test(logLine)) return 'high';

    // Server errors (5xx) on non-static paths
    if (/^5\d\d$/.test(status)) return 'medium';

    // Suspicious data transfer
    if (categories.includes('Data Transfer') && /\b(unusual|abnormal|exfil)\b/i.test(logLine)) return 'high';

    if (hasSecurityAlert) return 'high';
    if (hasAccessControl && !isSuccessResponse) return 'medium';

    return 'low';
  };

  const detectAdvancedThreats = (events) => {
    const threats = [];
    // ip → { failedIdxs, ports, timestamps, destIPs }
    const ipFailures = {};
    const portScansByIP = {};
    const seenThreatSigs = new Set();

    const addThreat = (t) => {
      const sig = t.type + '|' + (t.sourceIP || '') + '|' + (t.description || '').slice(0, 60);
      if (seenThreatSigs.has(sig)) return;
      seenThreatSigs.add(sig);
      threats.push(t);
    };

    events.forEach((event, idx) => {
      const ip = event.parameters.sourceIP || 'unknown';
      const logLine = event.originalLog || '';

      // --- Brute force / credential attack ---
      if (event.categories.includes('Login Attempts') && /\b(fail|denied|invalid|bad.*password|auth.*fail)\b/i.test(logLine)) {
        if (!ipFailures[ip]) ipFailures[ip] = { idxs: [], timestamps: [] };
        ipFailures[ip].idxs.push(idx);
        if (event.parameters.timestamp) ipFailures[ip].timestamps.push(event.parameters.timestamp);

        if (ipFailures[ip].idxs.length === 3) {
          const timeRange = ipFailures[ip].timestamps.length >= 2
            ? ` between ${ipFailures[ip].timestamps[0]} – ${ipFailures[ip].timestamps[ipFailures[ip].timestamps.length - 1]}`
            : '';
          addThreat({
            type: 'Brute Force Attack',
            severity: 'critical',
            sourceIP: ip,
            description: `${ipFailures[ip].idxs.length}+ failed login attempts from ${ip}${timeRange}`,
            recommendation: 'Block this IP immediately using firewall rules. Review authentication logs for successful logins. Implement account lockout policies.',
            mitigation: ['Block IP: ' + ip, 'Enable rate limiting', 'Implement CAPTCHA', 'Enable 2FA', 'Review password policies']
          });
        }
      }

      // --- Port scan detection ---
      const isPortScan = /\b(port.*scan|port scan|syn.*flood|scan.*detect)\b/i.test(logLine)
        || (event.categories.includes('Port Activity') && event.categories.includes('Security Alerts'));
      if (isPortScan) {
        if (!portScansByIP[ip]) portScansByIP[ip] = { idxs: [], ports: new Set(), timestamps: [], destIPs: new Set() };
        portScansByIP[ip].idxs.push(idx);
        if (event.parameters.timestamp) portScansByIP[ip].timestamps.push(event.parameters.timestamp);
        if (event.parameters.port) portScansByIP[ip].ports.add(event.parameters.port);
        if (event.parameters.destinationIP) portScansByIP[ip].destIPs.add(event.parameters.destinationIP);
        // Also pick up any bare port number from dport=/dst_port= notation
        const dportMatch = logLine.match(/\b(?:dport|dst_port|destination.*port)[=:\s]+(\d+)/i);
        if (dportMatch) portScansByIP[ip].ports.add(dportMatch[1]);
      }

      // --- DDoS ---
      if (/icmp.*packet|ping.*flood|large.*packet/i.test(logLine)) {
        addThreat({
          type: 'Possible DDoS Attack',
          severity: 'critical',
          sourceIP: ip,
          description: `Large ICMP packets / flood traffic detected from ${ip !== 'unknown' ? ip : 'multiple sources'}`,
          recommendation: 'Enable rate limiting immediately. Contact ISP for upstream filtering if needed.',
          mitigation: ['Enable rate limiting', 'Activate anti-DDoS rules', 'Contact ISP', 'Monitor bandwidth', 'Consider DDoS protection service']
        });
      }

      // --- Resource exhaustion ---
      if (event.threatLevel === 'critical' && /\b(disk|memory|cpu)\b/i.test(logLine)) {
        addThreat({
          type: 'Resource Exhaustion',
          severity: 'critical',
          description: 'Critical resource usage — possible DoS or system failure',
          recommendation: 'Investigate top processes immediately. Check for malicious activity or resource attacks.',
          mitigation: ['Identify resource-consuming processes', 'Kill suspicious processes', 'Clear logs/temp files', 'Check for attacks', 'Scale infrastructure']
        });
      }

      // --- Suspicious data transfer ---
      if (event.categories.includes('Data Transfer') && /\b(unusual|abnormal|exfil)\b/i.test(logLine)) {
        addThreat({
          type: 'Suspicious Data Transfer',
          severity: 'high',
          sourceIP: ip,
          description: `Unusual data transfer detected from ${ip} — possible exfiltration`,
          recommendation: 'Review destination IPs. Check for unauthorized transfers. Analyze traffic patterns.',
          mitigation: ['Review destination IPs', 'Block suspicious destinations', 'Investigate source', 'Check for unauthorized access', 'Review DLP policies']
        });
      }
    });

    // Emit port scan findings with full evidence
    Object.entries(portScansByIP).forEach(([ip, data]) => {
      if (data.idxs.length < 2) return;
      const portList = data.ports.size > 0 ? [...data.ports].sort((a, b) => Number(a) - Number(b)) : [];
      const destList = data.destIPs.size > 0 ? [...data.destIPs] : [];
      const timeRange = data.timestamps.length >= 2
        ? `${data.timestamps[0]} – ${data.timestamps[data.timestamps.length - 1]}`
        : (data.timestamps[0] || 'unknown time');
      const portDesc = portList.length > 0
        ? `targeting port${portList.length > 1 ? 's' : ''} ${portList.slice(0, 8).join(', ')}${portList.length > 8 ? '…' : ''}`
        : 'across multiple ports';
      const destDesc = destList.length > 0 ? ` → destination${destList.length > 1 ? 's' : ''}: ${destList.slice(0, 3).join(', ')}` : '';
      addThreat({
        type: 'Port Scan Attack',
        severity: 'high',
        sourceIP: ip,
        description: `${data.idxs.length} scan events from ${ip} ${portDesc}${destDesc} (${timeRange})`,
        evidence: {
          eventCount: data.idxs.length,
          ports: portList,
          destinations: destList,
          timeRange,
          confidence: Math.min(50 + data.idxs.length * 5, 95)
        },
        recommendation: 'Reconnaissance activity detected. Block source IP, enable IDS/IPS, and audit all open ports.',
        mitigation: ['Block IP: ' + ip, 'Enable IDS/IPS', 'Implement port-level rate limiting', 'Audit open services', 'Monitor for follow-up exploitation']
      });
    });

    return threats;
  };

  const generateIPIntelligence = (ip) => {
    const firstOctet = parseInt(ip.split('.')[0]);
    const secondOctet = parseInt(ip.split('.')[1]);
    
    if (firstOctet === 10 || (firstOctet === 172 && secondOctet >= 16 && secondOctet <= 31) || (firstOctet === 192 && secondOctet === 168)) {
      return { country: 'Local Network', city: 'Internal', isp: 'Private Network', risk: 'Low', type: 'Corporate' };
    } else if (firstOctet >= 203 && firstOctet <= 223) {
      const regions = [{ country: 'China', city: 'Beijing', isp: 'China Telecom' }, { country: 'Japan', city: 'Tokyo', isp: 'NTT' }, { country: 'India', city: 'Mumbai', isp: 'Tata' }];
      const region = regions[secondOctet % regions.length];
      return { ...region, risk: Math.random() > 0.6 ? 'High' : 'Medium', type: 'Residential' };
    } else if (firstOctet >= 198 && firstOctet <= 199) {
      const cities = ['Virginia', 'California', 'Oregon'];
      const isps = ['Amazon AWS', 'Google Cloud', 'Microsoft Azure'];
      return { country: 'United States', city: cities[secondOctet % 3], isp: isps[secondOctet % 3], risk: 'Medium', type: 'Datacenter' };
    } else {
      const regions = [{ country: 'United States', city: 'New York', isp: 'Verizon' }, { country: 'Germany', city: 'Frankfurt', isp: 'Hetzner' }, { country: 'Russia', city: 'Moscow', isp: 'Rostelecom' }];
      const region = regions[(firstOctet + secondOctet) % regions.length];
      return { ...region, risk: region.country === 'Russia' ? 'High' : 'Medium', type: 'Residential' };
    }
  };

  const parseTimestampToSeconds = (ts) => {
    if (!ts) return null;
    const hms = ts.match(/(\d{2}):(\d{2}):(\d{2})/);
    if (hms) return parseInt(hms[1]) * 3600 + parseInt(hms[2]) * 60 + parseInt(hms[3]);
    const hm = ts.match(/(\d{1,2}):(\d{2})(?!\d)/);
    if (hm) return parseInt(hm[1]) * 3600 + parseInt(hm[2]) * 60;
    return null;
  };

  const computeIntervalStats = (timestamps) => {
    const seconds = timestamps
      .map(ts => parseTimestampToSeconds(ts))
      .filter(s => s !== null)
      .sort((a, b) => a - b);
    if (seconds.length < 2) return null;
    const intervals = [];
    for (let i = 1; i < seconds.length; i++) {
      const d = seconds[i] - seconds[i - 1];
      if (d > 0) intervals.push(d);
    }
    if (intervals.length < 1) return null;
    const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    if (mean === 0) return null;
    const variance = intervals.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / intervals.length;
    return { mean, stdDev: Math.sqrt(variance), count: intervals.length };
  };

  const buildBehaviorSequence = (events) => {
    const sequence = [];
    let lastType = null;
    let count = 0;
    events.forEach(event => {
      const type = event.eventType;
      if (type === lastType) {
        count++;
      } else {
        if (lastType !== null) sequence.push({ type: lastType, count });
        lastType = type;
        count = 1;
      }
    });
    if (lastType !== null) sequence.push({ type: lastType, count });
    return sequence;
  };

  const buildUserSessions = (events) => {
    const sessions = {};
    events.forEach(event => {
      const user = event.parameters.user;
      const ip = event.parameters.sourceIP;
      const id = user || ip;
      if (!id) return;
      if (!sessions[id]) sessions[id] = { identifier: id, identifierType: user ? 'user' : 'ip', events: [], eventTypes: new Set(), timestamps: [] };
      sessions[id].events.push(event);
      sessions[id].eventTypes.add(event.eventType);
      if (event.parameters.timestamp) sessions[id].timestamps.push(event.parameters.timestamp);
    });
    return sessions;
  };

  const runInvestigationEngine = (events) => {
    const sessions = buildUserSessions(events);
    const findings = [];

    Object.values(sessions).forEach(session => {
      if (session.events.length < 3) return;
      const sessionFindings = [];

      // ── Rule 1: Automated polling ─────────────────────────────────────────
      const typeGroups = {};
      session.events.forEach(event => {
        const t = event.eventType;
        if (!typeGroups[t]) typeGroups[t] = [];
        typeGroups[t].push(event);
      });

      let bestAutomation = null;
      Object.entries(typeGroups).forEach(([type, evts]) => {
        if (evts.length < 4) return;
        const tsList = evts.map(e => e.parameters.timestamp).filter(Boolean);
        const stats = computeIntervalStats(tsList);
        if (!stats) return;
        const cv = stats.stdDev / stats.mean;
        // Confidence: CV drives base score, count adds up to +8 bonus
        let score = cv < 0.03 ? 95 : cv < 0.08 ? 86 : cv < 0.15 ? 74 : cv < 0.25 ? 58 : cv < 0.40 ? 42 : 0;
        if (score === 0) return;
        const countBonus = Math.min(Math.floor((evts.length - 4) / 3) * 2, 8);
        score = Math.min(score + countBonus, 99);
        if (!bestAutomation || score > bestAutomation.score) {
          const sortedTs = tsList
            .map(ts => ({ ts, secs: parseTimestampToSeconds(ts) }))
            .filter(x => x.secs !== null)
            .sort((a, b) => a.secs - b.secs);
          const sparklineData = sortedTs.slice(1).map((x, i) => ({ idx: i + 1, interval: x.secs - sortedTs[i].secs }));
          bestAutomation = { type, count: evts.length, stats, score, sparklineData };
        }
      });

      if (bestAutomation) {
        const intervalStr = bestAutomation.stats.mean.toFixed(1);
        const sigmaStr = bestAutomation.stats.stdDev.toFixed(2);
        sessionFindings.push({
          type: 'Automated API Polling',
          confidence: bestAutomation.score,
          icon: '🤖',
          detail: `"${bestAutomation.type}" called ${bestAutomation.count} times — mean interval ${intervalStr}s (σ = ${sigmaStr}s)`,
          evidence: [`${bestAutomation.count} calls to "${bestAutomation.type}"`, `Average interval: ${intervalStr}s`, `Std deviation: ${sigmaStr}s — near-zero indicates scripted timing`, `CV = ${(bestAutomation.stats.stdDev / bestAutomation.stats.mean).toFixed(3)}`],
          caseSummaryData: { type: 'automation', eventType: bestAutomation.type, count: bestAutomation.count, interval: intervalStr, sigma: sigmaStr },
          mitre: { id: 'T1071', name: 'Application Layer Protocol', tactic: 'Command and Control' },
          mitigations: ['Rate-limit or block this account/IP', 'Require re-authentication', 'Audit accessed data', 'Check for credential compromise'],
          sparklineData: bestAutomation.sparklineData
        });
      }

      // ── Rule 2: Reconnaissance ────────────────────────────────────────────
      if (session.eventTypes.size >= 5 && session.events.length >= 8) {
        // Score scales with endpoint variety and total request count
        const typeScore = Math.min(session.eventTypes.size * 7, 56); // max 56 from types
        const volScore = Math.min(Math.floor(session.events.length / 4) * 3, 24); // max 24 from volume
        const recon_confidence = Math.min(20 + typeScore + volScore, 82);
        sessionFindings.push({
          type: 'Potential Reconnaissance',
          confidence: recon_confidence,
          icon: '🔍',
          detail: `Accessed ${session.eventTypes.size} distinct endpoint types across ${session.events.length} requests`,
          evidence: [`${session.eventTypes.size} distinct API/endpoint types accessed`, `${session.events.length} total requests in this session`, `Endpoint types: ${[...session.eventTypes].slice(0, 5).join(', ')}${session.eventTypes.size > 5 ? '…' : ''}`],
          caseSummaryData: { type: 'recon', types: session.eventTypes.size, events: session.events.length },
          mitre: { id: 'T1595', name: 'Active Scanning', tactic: 'Reconnaissance' },
          mitigations: ['Review authorization per endpoint', 'Enable per-endpoint rate limiting', 'Flag account for manual review']
        });
      }

      // ── Rule 3: After-hours access ────────────────────────────────────────
      const afterHours = session.events.filter(e => {
        const s = parseTimestampToSeconds(e.parameters.timestamp || '');
        if (s === null) return false;
        const h = Math.floor(s / 3600);
        return h < 6 || h >= 22;
      });
      if (afterHours.length >= 2) {
        // Base 30, +6 per after-hours event (capped at 75), +10 if it's a large fraction of the session
        const afterFraction = afterHours.length / session.events.length;
        const ah_confidence = Math.min(30 + afterHours.length * 6 + (afterFraction > 0.5 ? 10 : 0), 75);
        const ahTimes = afterHours.map(e => e.parameters.timestamp).filter(Boolean);
        sessionFindings.push({
          type: 'After-Hours Access',
          confidence: ah_confidence,
          icon: '🌙',
          detail: `${afterHours.length} events outside business hours (before 06:00 or after 22:00)`,
          evidence: [`${afterHours.length} after-hours events`, ahTimes.length ? `Timestamps: ${ahTimes.slice(0, 3).join(', ')}${ahTimes.length > 3 ? '…' : ''}` : null, `${(afterFraction * 100).toFixed(0)}% of session activity was after-hours`].filter(Boolean),
          caseSummaryData: { type: 'afterhours', count: afterHours.length, times: ahTimes.slice(0, 3) },
          mitre: { id: 'T1078', name: 'Valid Accounts', tactic: 'Defense Evasion / Persistence' },
          mitigations: ['Verify after-hours access rights', 'Alert security team', 'Review for data exfiltration']
        });
      }

      // ── Rule 4: Brute force / credential stuffing ─────────────────────────
      const failedLogins = session.events.filter(e =>
        /\b(fail|denied|invalid|bad.*password)\b/i.test(e.originalLog) && /\b(login|auth|password)\b/i.test(e.originalLog)
      );
      if (failedLogins.length >= 3) {
        const hasSuccess = session.events.some((e, i) =>
          /\b(success|logged in|authenticated)\b/i.test(e.originalLog) && /\b(login|auth)\b/i.test(e.originalLog) &&
          session.events.slice(0, i).some(p => /\b(fail|denied|invalid)\b/i.test(p.originalLog))
        );
        // Scale: 3 fails = 62, each additional +5, cap at 88. Takeover adds 8 on top.
        const bf_base = Math.min(62 + (failedLogins.length - 3) * 5, 88);
        const bf_confidence = hasSuccess ? Math.min(bf_base + 8, 96) : bf_base;
        sessionFindings.push({
          type: hasSuccess ? 'Credential Stuffing / Account Takeover' : 'Brute Force Attempt',
          confidence: bf_confidence,
          icon: '🔑',
          detail: `${failedLogins.length} failed login attempt${failedLogins.length > 1 ? 's' : ''}${hasSuccess ? ' followed by successful authentication' : ''}`,
          evidence: [`${failedLogins.length} failed authentication events`, hasSuccess ? '✓ Successful login followed the failures — possible account takeover' : 'No subsequent successful login detected', failedLogins[0]?.parameters?.sourceIP ? `Source IP: ${failedLogins[0].parameters.sourceIP}` : null].filter(Boolean),
          caseSummaryData: { type: 'bruteforce', count: failedLogins.length, takeover: hasSuccess },
          mitre: hasSuccess
            ? { id: 'T1110.004', name: 'Credential Stuffing', tactic: 'Credential Access' }
            : { id: 'T1110', name: 'Brute Force', tactic: 'Credential Access' },
          mitigations: ['Lock account immediately', 'Force password reset', 'Block source IP', 'Enable MFA']
        });
      }

      // ── Rule 5: Session hijacking / multi-IP ─────────────────────────────
      if (session.identifierType === 'user') {
        const ipTimestamps = {};
        session.events.forEach(e => {
          const ip = e.parameters.sourceIP;
          if (!ip) return;
          const s = parseTimestampToSeconds(e.parameters.timestamp || '');
          if (s === null) return;
          if (!ipTimestamps[ip]) ipTimestamps[ip] = [];
          ipTimestamps[ip].push(s);
        });
        const distinctIPs = Object.keys(ipTimestamps);
        if (distinctIPs.length >= 2) {
          const ranges = distinctIPs.map(ip => ({ ip, min: Math.min(...ipTimestamps[ip]), max: Math.max(...ipTimestamps[ip]) }));
          const overlapping = [];
          for (let i = 0; i < ranges.length; i++) {
            for (let j = i + 1; j < ranges.length; j++) {
              if (ranges[i].min <= ranges[j].max && ranges[j].min <= ranges[i].max) {
                if (!overlapping.includes(ranges[i].ip)) overlapping.push(ranges[i].ip);
                if (!overlapping.includes(ranges[j].ip)) overlapping.push(ranges[j].ip);
              }
            }
          }
          if (overlapping.length >= 2) {
            // Score scales with number of overlapping IPs
            const hijack_conf = Math.min(72 + (overlapping.length - 2) * 6, 92);
            sessionFindings.push({
              type: 'Possible Session Hijacking',
              confidence: hijack_conf,
              icon: '👥',
              detail: `User active simultaneously from ${overlapping.length} IPs: ${overlapping.join(', ')}`,
              evidence: [`${overlapping.length} source IPs with overlapping active time windows`, `IPs: ${overlapping.join(', ')}`, 'Simultaneous activity from different IPs for the same account is a strong hijacking indicator'],
              caseSummaryData: { type: 'hijacking', ips: overlapping },
              mitre: { id: 'T1563', name: 'Remote Service Session Hijacking', tactic: 'Lateral Movement' },
              mitigations: ['Invalidate all active sessions', 'Force re-authentication', 'Investigate both source IPs', 'Enable geo-velocity checks']
            });
          } else {
            // Non-overlapping multi-IP: lower confidence
            const multiip_conf = Math.min(30 + distinctIPs.length * 7, 52);
            sessionFindings.push({
              type: 'Multi-IP Access',
              confidence: multiip_conf,
              icon: '🔀',
              detail: `Same user accessed from ${distinctIPs.length} different IPs: ${distinctIPs.join(', ')}`,
              evidence: [`${distinctIPs.length} distinct source IPs used`, `IPs: ${distinctIPs.join(', ')}`, 'Non-overlapping — may indicate VPN switching or shared credential'],
              caseSummaryData: { type: 'multiip', ips: distinctIPs },
              mitre: { id: 'T1078', name: 'Valid Accounts', tactic: 'Defense Evasion' },
              mitigations: ['Verify legitimate device switching', 'Check for shared credential use', 'Review access locations']
            });
          }
        }
      }

      // ── Rule 6: Endpoint enumeration ──────────────────────────────────────
      if (session.events.length >= 5) {
        const sortedByTime = session.events
          .map(e => ({ type: e.eventType, ts: parseTimestampToSeconds(e.parameters.timestamp || '') }))
          .filter(e => e.ts !== null)
          .sort((a, b) => a.ts - b.ts);
        let bestEnumeration = null;
        for (let i = 0; i < sortedByTime.length; i++) {
          const windowEnd = sortedByTime[i].ts + 120;
          const inWindow = sortedByTime.filter(e => e.ts >= sortedByTime[i].ts && e.ts <= windowEnd);
          const distinct = new Set(inWindow.map(e => e.type));
          if (distinct.size >= 4 && inWindow.length >= 6) {
            // Score: distinct types * 8 + extra events bonus, min 48
            const enum_conf = Math.min(24 + distinct.size * 9 + Math.max(0, inWindow.length - 6) * 2, 88);
            if (!bestEnumeration || enum_conf > bestEnumeration.score) {
              bestEnumeration = { distinct, inWindow, score: enum_conf };
            }
          }
        }
        if (bestEnumeration) {
          sessionFindings.push({
            type: 'Endpoint Enumeration',
            confidence: bestEnumeration.score,
            icon: '📡',
            detail: `${bestEnumeration.distinct.size} distinct endpoint types accessed within a 2-minute window (${bestEnumeration.inWindow.length} requests)`,
            evidence: [`${bestEnumeration.distinct.size} distinct endpoint types in 120s window`, `${bestEnumeration.inWindow.length} total requests in window`, `Types: ${[...bestEnumeration.distinct].join(', ')}`],
            caseSummaryData: { type: 'enumeration', types: bestEnumeration.distinct.size, count: bestEnumeration.inWindow.length },
            mitre: { id: 'T1046', name: 'Network Service Discovery', tactic: 'Discovery' },
            mitigations: ['Enable anomaly-based rate limiting', 'Review all accessed endpoints', 'Audit authorization logs']
          });
        }
      }

      if (sessionFindings.length > 0) {
        // Sort findings within session by confidence desc
        sessionFindings.sort((a, b) => b.confidence - a.confidence);
        const maxConf = sessionFindings[0].confidence;
        const tier = maxConf >= 88 ? 'critical' : maxConf >= 65 ? 'review' : 'info';

        // Generate case summary paragraph
        const topFinding = sessionFindings[0];
        const d = topFinding.caseSummaryData || {};
        let caseSummary = '';
        const entity = session.identifierType === 'user' ? `User ${session.identifier}` : `IP ${session.identifier}`;
        if (d.type === 'automation') {
          caseSummary = `${entity} issued ${d.count} "${d.eventType}" requests with a near-constant interval of ${d.interval}s (σ = ${d.sigma}s). The request cadence is machine-consistent — this is not interactive human behavior. Likely a script, integration, or compromised automated process.`;
        } else if (d.type === 'bruteforce') {
          caseSummary = `${entity} generated ${d.count} authentication failures${d.takeover ? ', followed by a successful login — indicating likely account takeover' : ' with no subsequent success'}. This pattern is consistent with credential brute-forcing or a credential stuffing campaign.`;
        } else if (d.type === 'hijacking') {
          caseSummary = `${entity} was concurrently active from ${d.ips.length} different source IPs (${d.ips.join(', ')}). Simultaneous sessions from multiple IPs for the same account strongly suggest session token theft or credential sharing.`;
        } else if (d.type === 'recon') {
          caseSummary = `${entity} accessed ${d.types} distinct endpoint types across ${d.events} requests. This breadth-first access pattern is consistent with automated reconnaissance or API enumeration.`;
        } else if (d.type === 'afterhours') {
          caseSummary = `${entity} generated ${d.count} access events outside business hours${d.times?.length ? ` (${d.times.join(', ')})` : ''}. After-hours access without prior authorization may indicate compromised credentials or insider activity.`;
        } else if (d.type === 'enumeration') {
          caseSummary = `${entity} accessed ${d.types} distinct endpoint types within a 2-minute window across ${d.count} requests. This burst pattern is characteristic of automated endpoint discovery.`;
        } else if (d.type === 'multiip') {
          caseSummary = `${entity} accessed the system from ${d.ips.length} different source IPs. While potentially legitimate (VPN, mobile), this warrants verification — especially if IPs span different countries or networks.`;
        } else {
          caseSummary = `${entity} exhibited ${sessionFindings.length} behavioral anomal${sessionFindings.length > 1 ? 'ies' : 'y'} across ${session.events.length} events. Manual review is recommended.`;
        }

        // Include chronological events for the investigation timeline (cap at 60)
        const sortedEvents = [...session.events].sort((a, b) => {
          const sa = parseTimestampToSeconds(a.parameters.timestamp || '');
          const sb = parseTimestampToSeconds(b.parameters.timestamp || '');
          return (sa ?? 0) - (sb ?? 0);
        });

        findings.push({
          identifier: session.identifier,
          identifierType: session.identifierType,
          totalEvents: session.events.length,
          uniqueEventTypes: session.eventTypes.size,
          behaviorSequence: buildBehaviorSequence(session.events),
          riskScore: maxConf,
          tier,
          caseSummary,
          sessionEvents: sortedEvents.slice(0, 60),
          findings: sessionFindings
        });
      }
    });

    return findings.sort((a, b) => b.riskScore - a.riskScore);
  };

  const analyzeFromPaste = () => {
    if (!logText.trim()) return;
    setLoading(true);
    setTimeout(() => {
      try { analyzeLogFile(logText.trim(), 'pasted_log.txt'); }
      catch (e) { console.error('Paste analysis error:', e); alert(`Analysis error: ${e?.message || 'Unknown error'}`); }
      finally { setLoading(false); }
    }, 300);
  };

  const generateReport = () => {
    if (!analysis) return;
    const timestamp = new Date().toLocaleString();
    const filename = analysis.stats.fileName || 'Unknown';
    const inv = analysis.investigation || [];
    const threats = analysis.threats || [];

    // ── helpers ────────────────────────────────────────────────────────────
    const pct = (n) => analysis.stats.total > 0 ? ((n / analysis.stats.total) * 100).toFixed(1) : '0.0';
    const esc = (s) => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');

    // Severity level + color
    const overallRisk = analysis.stats.critical > 0 ? 'CRITICAL'
      : analysis.stats.high > 10 ? 'HIGH'
      : analysis.stats.high > 0 ? 'MEDIUM-HIGH'
      : analysis.stats.medium > 0 ? 'MEDIUM' : 'LOW';
    const riskBg = { CRITICAL:'#dc2626', HIGH:'#ea580c', 'MEDIUM-HIGH':'#d97706', MEDIUM:'#ca8a04', LOW:'#16a34a' }[overallRisk];

    // ── narrative: explain what drove severity counts ──────────────────────
    const catEntries = Object.entries(analysis.stats.categoryBreakdown).sort(([,a],[,b]) => b-a);
    const topCat = catEntries[0]?.[0] || 'Unknown';
    const topCatCount = catEntries[0]?.[1] || 0;
    const topCatPct = pct(topCatCount);

    // Figure out dominant high-event driver
    const highEvents = analysis.results.filter(r => r.threatLevel === 'high');
    const highCatMap = {};
    highEvents.forEach(r => r.categories.forEach(c => { highCatMap[c] = (highCatMap[c]||0)+1; }));
    const topHighCat = Object.entries(highCatMap).sort(([,a],[,b])=>b-a)[0];
    const highNarrative = analysis.stats.high > 0
      ? (topHighCat
          ? `The ${analysis.stats.high.toLocaleString()} High-severity events were predominantly driven by <strong>${topHighCat[0]}</strong> activity (${topHighCat[1].toLocaleString()} events, ${pct(topHighCat[1])}% of total). Review whether these represent confirmed malicious intent or expected operational traffic before escalating.`
          : `${analysis.stats.high.toLocaleString()} events were classified High severity. Manual review is required to distinguish genuine threats from expected activity.`)
      : 'No High-severity events were detected.';

    const critNarrative = analysis.stats.critical > 0
      ? `<strong>${analysis.stats.critical.toLocaleString()} Critical events</strong> were detected. These require immediate triage — they match known attack signatures (brute force, active exploitation, or explicit intrusion indicators).`
      : 'No Critical events were detected in this log file.';

    // ── top IPs (from ipProfiles) ──────────────────────────────────────────
    const topIPs = Object.entries(analysis.ipProfiles || {})
      .sort(([,a],[,b]) => b.events - a.events).slice(0, 10)
      .map(([ip, p]) => ({ ip, ...p, intel: analysis.ipIntelligence?.[ip], users: [...p.users] }));

    // ── unique affected users ──────────────────────────────────────────────
    const userMap = {};
    analysis.results.forEach(r => {
      const u = r.parameters.user;
      if (!u) return;
      if (!userMap[u]) userMap[u] = { events: 0, threats: 0, failedLogins: 0, ips: new Set() };
      userMap[u].events++;
      if (r.isAlert) userMap[u].threats++;
      if (r.categories.includes('Login Attempts') && /\b(fail|denied|invalid)\b/i.test(r.originalLog)) userMap[u].failedLogins++;
      if (r.parameters.sourceIP) userMap[u].ips.add(r.parameters.sourceIP);
    });
    const topUsers = Object.entries(userMap).sort(([,a],[,b]) => b.threats - a.threats).slice(0, 10);

    // ── evidence timeline: top 30 non-low events ──────────────────────────
    const evidenceEvents = analysis.results
      .filter(r => r.threatLevel !== 'low')
      .slice(0, 30);

    // ── category breakdown bar rows ───────────────────────────────────────
    const maxCat = catEntries[0]?.[1] || 1;
    const catRows = catEntries.slice(0, 14).map(([cat, count]) => {
      const barW = Math.round((count / maxCat) * 100);
      return `<tr>
        <td>${esc(cat)}</td>
        <td><div style="display:flex;align-items:center;gap:8px">
          <div style="flex:1;height:8px;background:#e2e8f0;border-radius:4px;overflow:hidden">
            <div style="width:${barW}%;height:100%;background:#3b82f6;border-radius:4px"></div>
          </div>
          <span style="font-weight:700;color:#1e3a5f;min-width:36px;text-align:right">${count.toLocaleString()}</span>
        </div></td>
        <td style="color:#64748b;white-space:nowrap">${pct(count)}%</td>
      </tr>`;
    }).join('');

    // ── threat cards ──────────────────────────────────────────────────────
    const threatCards = threats.length > 0 ? threats.map((t, i) => {
      const sev = t.severity || 'medium';
      const evCount = t.evidence?.eventCount;
      const ports = t.evidence?.ports?.length ? t.evidence.ports.slice(0,8).join(', ') : null;
      const conf = t.evidence?.confidence;
      return `<div class="card ${sev}">
        <div class="card-header">
          <span class="card-num">THREAT ${i+1}</span>
          <span class="card-title">${esc(t.type)}</span>
          <span class="badge ${sev}">${sev.toUpperCase()}</span>
        </div>
        ${t.sourceIP ? `<div class="meta-pill">Source IP: <strong>${esc(t.sourceIP)}</strong></div>` : ''}
        <p class="desc">${esc(t.description)}</p>
        ${evCount !== undefined ? `<div class="evidence-row"><span>📊 ${evCount} matching events</span>${ports ? `<span>🔌 Ports: ${esc(ports)}</span>` : ''}${conf ? `<span>🎯 ${conf}% confidence</span>` : ''}</div>` : ''}
        <p class="rec-label">Recommendation</p>
        <p class="desc">${esc(t.recommendation)}</p>
        ${t.mitigation?.length ? `<div class="chips">${t.mitigation.map(m=>`<span class="chip">${esc(m)}</span>`).join('')}</div>` : ''}
      </div>`;
    }).join('') : `<div class="clean-card">✅ No confirmed threats detected. Monitor for emerging patterns.</div>`;

    // ── investigation finding cards ───────────────────────────────────────
    const invCards = inv.length > 0 ? inv.map((session, i) => {
      const riskCls = session.riskScore >= 90 ? 'critical' : session.riskScore >= 70 ? 'high' : 'medium';
      const subCards = session.findings.map(f => {
        const confCls = f.confidence >= 90 ? 'conf-crit' : f.confidence >= 70 ? 'conf-high' : 'conf-med';
        const mitreBadge = f.mitre ? `<span class="mitre-badge">${esc(f.mitre.id)}</span><span class="tactic-badge">${esc(f.mitre.tactic)}</span>` : '';
        return `<div class="sub-card">
          <div class="sub-header">
            <span>${f.icon} <strong>${esc(f.type)}</strong> ${mitreBadge}</span>
            <span class="conf ${confCls}">${f.confidence}% confidence</span>
          </div>
          <p class="desc">${esc(f.detail)}</p>
          ${f.mitre ? `<p class="mitre-line">MITRE ATT&amp;CK · <strong>${esc(f.mitre.id)}</strong> · ${esc(f.mitre.name)} · Tactic: ${esc(f.mitre.tactic)}</p>` : ''}
          <div class="chips">${(f.mitigations||[]).map(m=>`<span class="chip">${esc(m)}</span>`).join('')}</div>
        </div>`;
      }).join('');

      const seqText = session.behaviorSequence.map(s=>`${s.type}${s.count>1?` ×${s.count}`:''}`).join(' → ');
      return `<div class="card ${riskCls}">
        <div class="card-header">
          <span class="card-num">FINDING ${i+1}</span>
          <span class="card-title">${session.identifierType === 'user' ? '👤' : '🌐'} ${esc(session.identifier)}</span>
          <span class="risk-score" style="color:${riskCls==='critical'?'#dc2626':riskCls==='high'?'#ea580c':'#ca8a04'}">${session.riskScore}/100</span>
        </div>
        <div class="meta">${session.totalEvents} events · ${session.uniqueEventTypes} endpoint types</div>
        <div class="seq-label">Behavior Sequence</div>
        <div class="seq">${esc(seqText)}</div>
        ${subCards}
      </div>`;
    }).join('') : `<div class="clean-card">✅ No suspicious behavioral sessions detected.</div>`;

    // ── affected users table ──────────────────────────────────────────────
    const userRows = topUsers.length > 0 ? topUsers.map(([u, d]) => `<tr>
      <td style="font-family:monospace;font-weight:600">${esc(u)}</td>
      <td>${d.events.toLocaleString()}</td>
      <td style="font-weight:700;color:${d.threats>0?'#ea580c':'#16a34a'}">${d.threats}</td>
      <td style="color:${d.failedLogins>0?'#dc2626':'#334155'}">${d.failedLogins}</td>
      <td>${[...d.ips].slice(0,3).join(', ')}</td>
    </tr>`).join('') : `<tr><td colspan="5" style="color:#94a3b8;text-align:center">No authenticated user activity found</td></tr>`;

    // ── affected IPs table ────────────────────────────────────────────────
    const ipRows = topIPs.map((item, i) => {
      const riskColor = item.intel?.risk==='High'?'#dc2626':item.intel?.risk==='Medium'?'#ea580c':'#16a34a';
      return `<tr>
        <td>${i+1}</td>
        <td style="font-family:monospace;font-weight:600">${esc(item.ip)}</td>
        <td>${item.intel?`${esc(item.intel.country)}, ${esc(item.intel.city)}`:'—'}</td>
        <td style="font-weight:700;color:${riskColor}">${item.intel?.risk||'—'}</td>
        <td>${item.events.toLocaleString()}</td>
        <td style="color:${item.threats>0?'#ea580c':'#16a34a'}">${item.threats}</td>
        <td style="color:${item.failedLogins>0?'#dc2626':'#334155'}">${item.failedLogins}</td>
      </tr>`;
    }).join('');

    // ── evidence timeline ─────────────────────────────────────────────────
    const sevColor = {critical:'#dc2626',high:'#ea580c',medium:'#ca8a04',low:'#64748b'};
    const sevBg = {critical:'#fef2f2',high:'#fff7ed',medium:'#fefce8',low:'#f8fafc'};
    const timelineRows = evidenceEvents.map((r, i) => {
      const ts = r.parameters.timestamp || '—';
      const user = r.parameters.user ? `<span style="color:#1d4ed8;font-size:11px">👤 ${esc(r.parameters.user)}</span>` : '';
      const ip = r.parameters.sourceIP ? `<span style="color:#64748b;font-size:11px">🌐 ${esc(r.parameters.sourceIP)}</span>` : '';
      return `<div style="display:flex;gap:0;margin-bottom:2px;align-items:stretch">
        <div style="width:3px;background:${sevColor[r.threatLevel]||'#94a3b8'};border-radius:2px;flex-shrink:0"></div>
        <div style="flex:1;padding:8px 12px;background:${sevBg[r.threatLevel]||'#f8fafc'};border-radius:0 6px 6px 0;margin-left:2px">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:3px;flex-wrap:wrap;gap:4px">
            <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
              <span style="font-family:monospace;font-size:11px;color:#64748b">${esc(ts)}</span>
              <span style="font-size:11px;font-weight:700;color:${sevColor[r.threatLevel]||'#64748b'};text-transform:uppercase">${r.threatLevel}</span>
              <span style="font-size:12px;font-weight:600;color:#1e3a5f">${esc(r.eventType)}</span>
            </div>
            <div style="display:flex;gap:8px">${user}${ip}</div>
          </div>
          <div style="font-family:monospace;font-size:11px;color:#475569;word-break:break-all">${esc(r.originalLog.slice(0,180))}${r.originalLog.length>180?'…':''}</div>
        </div>
      </div>`;
    }).join('');

    // ── recommendations ───────────────────────────────────────────────────
    const recs = [];
    // Session-specific recommendations
    inv.slice(0, 5).forEach(session => {
      session.findings.forEach(f => {
        if (f.type === 'Automated API Polling') {
          recs.push({ priority:'HIGH', action:`Investigate ${session.identifierType === 'user' ? 'user' : 'IP'} <strong>${esc(session.identifier)}</strong> for scripted/automated access`, detail:`${f.detail}. Verify if this is an authorized integration. If not, rotate credentials and block.` });
        } else if (f.type.includes('Brute Force') || f.type.includes('Credential')) {
          recs.push({ priority:'CRITICAL', action:`Lock account <strong>${esc(session.identifier)}</strong> and force password reset`, detail:`${f.detail}. Block source IP(s) and audit all successful logins from this account in the last 30 days.` });
        } else if (f.type.includes('Hijacking')) {
          recs.push({ priority:'HIGH', action:`Invalidate all active sessions for <strong>${esc(session.identifier)}</strong>`, detail:`${f.detail}. Investigate both source IPs and enable geo-velocity alerting.` });
        } else if (f.type.includes('After-Hours')) {
          recs.push({ priority:'MEDIUM', action:`Review after-hours activity for <strong>${esc(session.identifier)}</strong>`, detail:`${f.detail}. Confirm legitimate access or investigate for insider threat / compromised credentials.` });
        }
      });
    });
    // Threat-specific recommendations
    threats.forEach(t => {
      if (t.sourceIP) recs.push({ priority: t.severity.toUpperCase(), action: `Block source IP <strong>${esc(t.sourceIP)}</strong> at the perimeter firewall`, detail: t.description });
    });
    // Fallback generic recs
    if (recs.length === 0) {
      recs.push({ priority:'LOW', action:'Continue routine log monitoring', detail:'No specific actionable indicators identified. Maintain current security posture and review alert thresholds quarterly.' });
    }
    recs.push({ priority:'INFO', action:`Schedule follow-up review within ${analysis.stats.critical > 0 ? '24 hours' : '7 days'}`, detail:'Re-analyze after any remediation steps to confirm threats are neutralized.' });

    const recPriorityColor = {CRITICAL:'#dc2626',HIGH:'#ea580c','MEDIUM-HIGH':'#d97706',MEDIUM:'#ca8a04',LOW:'#16a34a',INFO:'#3b82f6'};
    const recCards = recs.map((r,i) => `<div class="rec-card">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
        <span style="font-size:11px;font-weight:800;padding:2px 10px;border-radius:99px;background:${recPriorityColor[r.priority]||'#64748b'};color:white">${r.priority}</span>
        <span style="font-weight:700;color:#1e3a5f;font-size:13px">${r.action}</span>
      </div>
      <p style="font-size:12px;color:#475569;line-height:1.5">${r.detail}</p>
    </div>`).join('');

    // ── appendix: top 50 non-low events ───────────────────────────────────
    const appendixEvents = analysis.results.filter(r=>r.threatLevel!=='low').slice(0,50);
    const appendixRows = appendixEvents.map(r=>`<tr>
      <td style="font-family:monospace;font-size:11px;color:#64748b">${esc(r.parameters.timestamp||'—')}</td>
      <td><span style="font-size:10px;font-weight:700;padding:1px 7px;border-radius:99px;background:${sevColor[r.threatLevel]||'#94a3b8'};color:white">${r.threatLevel.toUpperCase()}</span></td>
      <td style="font-size:12px;color:#1e3a5f;font-weight:600">${esc(r.eventType)}</td>
      <td style="font-family:monospace;font-size:10px;color:#475569;word-break:break-all">${esc(r.originalLog.slice(0,120))}${r.originalLog.length>120?'…':''}</td>
    </tr>`).join('');

    // ── CSS ───────────────────────────────────────────────────────────────
    const css = `
      *{margin:0;padding:0;box-sizing:border-box}
      body{font-family:'Segoe UI',Arial,sans-serif;color:#1a1a2e;background:#fff;padding:40px;max-width:960px;margin:0 auto;line-height:1.55}
      @media print{body{padding:20px;font-size:12px}.no-print{display:none!important}@page{margin:15mm;size:A4}
        .page-break{page-break-before:always}.avoid-break{page-break-inside:avoid}}
      h1{font-size:28px;font-weight:800;color:#1e3a5f}
      h2{font-size:13px;font-weight:700;color:#1e3a5f;border-left:4px solid #3b82f6;padding-left:10px;margin-bottom:14px;text-transform:uppercase;letter-spacing:.07em}
      .section{margin-bottom:40px}
      /* Cover */
      .cover{border-bottom:4px solid #3b82f6;padding-bottom:28px;margin-bottom:36px}
      .logo{background:linear-gradient(135deg,#3b82f6,#06b6d4);color:white;padding:5px 14px;border-radius:8px;font-size:14px;font-weight:800;display:inline-block;margin-bottom:14px;letter-spacing:.02em}
      .report-meta{color:#64748b;font-size:13px;margin-top:10px;display:flex;gap:14px;flex-wrap:wrap}
      .risk-badge{display:inline-block;padding:5px 18px;border-radius:99px;font-size:13px;font-weight:800;background:${riskBg};color:white;margin-left:6px;vertical-align:middle}
      /* Stats */
      .stats-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px}
      .stat-box{border-radius:10px;padding:16px 12px;text-align:center;border:1px solid}
      .stat-box.critical{background:#fef2f2;border-color:#fca5a5}.stat-box.high{background:#fff7ed;border-color:#fed7aa}
      .stat-box.medium{background:#fefce8;border-color:#fde68a}.stat-box.low{background:#f0fdf4;border-color:#86efac}
      .stat-num{font-size:32px;font-weight:800;line-height:1}
      .stat-box.critical .stat-num{color:#dc2626}.stat-box.high .stat-num{color:#ea580c}
      .stat-box.medium .stat-num{color:#ca8a04}.stat-box.low .stat-num{color:#16a34a}
      .stat-label{font-size:10px;color:#64748b;font-weight:700;margin-top:5px;text-transform:uppercase;letter-spacing:.05em}
      .stat-reason{font-size:10px;color:#94a3b8;margin-top:3px;line-height:1.4}
      .summary-pills{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px}
      .pill{background:#f1f5f9;border:1px solid #e2e8f0;border-radius:99px;padding:4px 12px;font-size:12px;color:#334155}
      .pill strong{color:#1e3a5f}
      /* Narrative */
      .narrative{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:16px 20px;font-size:13px;color:#334155;line-height:1.7;margin-bottom:16px}
      .narrative strong{color:#1e3a5f}
      /* Cards */
      .card{border-radius:8px;padding:16px;margin-bottom:12px;border-left:4px solid}
      .card.critical{background:#fef2f2;border-color:#dc2626}.card.high{background:#fff7ed;border-color:#ea580c}
      .card.medium{background:#fefce8;border-color:#ca8a04}.card.low{background:#f0fdf4;border-color:#16a34a}
      .card-header{display:flex;align-items:center;gap:10px;margin-bottom:8px;flex-wrap:wrap}
      .card-num{color:#94a3b8;font-size:10px;font-weight:700;letter-spacing:.05em}
      .card-title{font-weight:700;font-size:15px;color:#1e3a5f;flex:1}
      .badge{padding:2px 10px;border-radius:99px;font-size:11px;font-weight:700}
      .badge.critical{background:#dc2626;color:white}.badge.high{background:#ea580c;color:white}
      .badge.medium{background:#ca8a04;color:white}.badge.low{background:#16a34a;color:white}
      .risk-score{font-size:15px;font-weight:800}
      .meta-pill{display:inline-block;background:#e0f2fe;color:#0369a1;border-radius:99px;padding:2px 10px;font-size:11px;font-weight:600;margin-bottom:8px}
      .evidence-row{display:flex;gap:14px;font-size:12px;color:#475569;margin:6px 0 8px;flex-wrap:wrap}
      .desc{color:#475569;font-size:13px;margin-bottom:8px;line-height:1.6}
      .rec-label{font-size:10px;font-weight:700;color:#3b82f6;margin-bottom:3px;text-transform:uppercase;letter-spacing:.04em}
      .meta{font-size:12px;color:#64748b;margin-bottom:10px}
      .seq-label{font-size:10px;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:.05em;margin-bottom:4px}
      .seq{font-family:'Consolas',monospace;font-size:12px;color:#1e3a5f;background:#f1f5f9;padding:10px 14px;border-radius:6px;margin-bottom:12px;word-break:break-word;line-height:1.7}
      .sub-card{background:white;border-radius:6px;padding:12px;margin-top:10px;border:1px solid #e2e8f0}
      .sub-header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:6px;flex-wrap:wrap;gap:6px}
      .sub-header>span:first-child{font-size:13px;color:#1e3a5f;flex:1}
      .conf{font-size:11px;font-weight:700;padding:2px 8px;border-radius:99px;color:white}
      .conf-crit{background:#dc2626}.conf-high{background:#ea580c}.conf-med{background:#ca8a04}
      .mitre-badge{font-family:monospace;font-size:11px;padding:1px 7px;border-radius:4px;background:#ede9fe;color:#7c3aed;font-weight:700;margin-left:4px}
      .tactic-badge{font-size:10px;padding:1px 7px;border-radius:4px;background:#f3f4f6;color:#6b7280;margin-left:4px}
      .mitre-line{font-size:11px;color:#7c3aed;background:#ede9fe;padding:4px 10px;border-radius:4px;margin:6px 0}
      .chips{display:flex;flex-wrap:wrap;gap:5px;margin-top:8px}
      .chip{font-size:11px;padding:3px 10px;border-radius:99px;background:#dbeafe;color:#1d4ed8;font-weight:600}
      .clean-card{background:#f0fdf4;border:1px solid #86efac;border-radius:8px;padding:16px;color:#15803d;font-weight:600;display:flex;align-items:center;gap:8px}
      /* Tables */
      table{width:100%;border-collapse:collapse;font-size:13px}
      th{text-align:left;padding:8px 10px;background:#f1f5f9;color:#475569;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;border-bottom:2px solid #e2e8f0}
      td{padding:8px 10px;border-bottom:1px solid #f1f5f9;color:#334155;vertical-align:middle}
      tr:hover td{background:#fafafa}
      /* Recommendations */
      .rec-card{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:14px 16px;margin-bottom:10px}
      /* Footer */
      .footer{margin-top:48px;padding-top:16px;border-top:2px solid #e2e8f0;color:#94a3b8;font-size:11px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px}
      .footer .brand{color:#3b82f6;font-weight:700}
      .print-btn{position:fixed;top:20px;right:20px;background:#3b82f6;color:white;border:none;padding:10px 22px;border-radius:8px;cursor:pointer;font-size:14px;font-weight:600;box-shadow:0 4px 14px rgba(59,130,246,.35);z-index:999}
      .print-btn:hover{background:#2563eb}
      .section-num{color:#3b82f6;font-weight:800;margin-right:6px}
    `;

    const html = `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CyberNyx Security Report — ${esc(filename)}</title>
<style>${css}</style>
</head><body>

<button class="print-btn no-print" onclick="window.print()">&#x1F4BE; Save as PDF</button>

<!-- COVER -->
<div class="cover">
  <div class="logo">⚡ CyberNyx</div>
  <h1>Security Investigation Report</h1>
  <div style="margin-top:10px;font-size:16px;color:#475569">
    Overall Risk Assessment: <span class="risk-badge">${overallRisk}</span>
  </div>
  <div class="report-meta">
    <span>📁 Source: <strong>${esc(filename)}</strong></span>
    <span>🕐 Generated: <strong>${timestamp}</strong></span>
    <span>📊 ${analysis.stats.total.toLocaleString()} total events</span>
    <span>🔍 ${analysis.stats.uniqueIPs} unique IPs</span>
  </div>
</div>

<!-- 1. EXECUTIVE SUMMARY -->
<div class="section">
  <h2><span class="section-num">1</span>Executive Summary</h2>
  <div class="stats-grid">
    <div class="stat-box critical">
      <div class="stat-num">${analysis.stats.critical.toLocaleString()}</div>
      <div class="stat-label">Critical</div>
      <div class="stat-reason">${analysis.stats.critical > 0 ? 'Immediate action required' : 'None detected'}</div>
    </div>
    <div class="stat-box high">
      <div class="stat-num">${analysis.stats.high.toLocaleString()}</div>
      <div class="stat-label">High</div>
      <div class="stat-reason">${analysis.stats.high > 0 ? 'Review within 24 hours' : 'None detected'}</div>
    </div>
    <div class="stat-box medium">
      <div class="stat-num">${analysis.stats.medium.toLocaleString()}</div>
      <div class="stat-label">Medium</div>
      <div class="stat-reason">${analysis.stats.medium > 0 ? 'Investigate this week' : 'None detected'}</div>
    </div>
    <div class="stat-box low">
      <div class="stat-num">${analysis.stats.low.toLocaleString()}</div>
      <div class="stat-label">Low / Info</div>
      <div class="stat-reason">Routine activity</div>
    </div>
  </div>
  <div class="summary-pills">
    <span class="pill"><strong>${analysis.stats.total.toLocaleString()}</strong> events parsed</span>
    <span class="pill"><strong>${analysis.stats.uniqueIPs}</strong> unique source IPs</span>
    <span class="pill"><strong>${Object.keys(analysis.stats.categoryBreakdown).length}</strong> event categories</span>
    <span class="pill"><strong>${threats.length}</strong> active threat${threats.length!==1?'s':''}</span>
    <span class="pill"><strong>${inv.length}</strong> suspicious session${inv.length!==1?'s':''}</span>
    <span class="pill"><strong>${topUsers.length}</strong> affected user${topUsers.length!==1?'s':''}</span>
  </div>
</div>

<!-- 2. KEY FINDINGS NARRATIVE -->
<div class="section">
  <h2><span class="section-num">2</span>Key Findings — Why It Matters</h2>
  <div class="narrative">${critNarrative}</div>
  <div class="narrative">${highNarrative}</div>
  ${inv.length > 0 ? `<div class="narrative">
    The behavioral analysis engine identified <strong>${inv.length} suspicious session${inv.length!==1?'s':''}</strong>.
    The highest-risk entity is <strong>${esc(inv[0].identifier)}</strong> (risk score ${inv[0].riskScore}/100),
    flagged for: ${inv[0].findings.map(f=>`<strong>${esc(f.type)}</strong>`).join(', ')}.
    ${inv[0].findings[0]?.mitre ? `This maps to MITRE ATT&amp;CK technique <strong>${esc(inv[0].findings[0].mitre.id)} — ${esc(inv[0].findings[0].mitre.name)}</strong>.` : ''}
  </div>` : ''}
  ${threats.length > 0 ? `<div class="narrative">
    <strong>${threats.length} confirmed threat${threats.length!==1?'s were':' was'} detected</strong>:
    ${threats.map(t=>`<strong>${esc(t.type)}</strong>`).join(', ')}.
    ${threats.some(t=>t.sourceIP) ? `Source IPs involved: ${[...new Set(threats.filter(t=>t.sourceIP).map(t=>t.sourceIP))].join(', ')}.` : ''}
  </div>` : ''}
</div>

<!-- 3. ACTIVE THREATS -->
<div class="section page-break avoid-break">
  <h2><span class="section-num">3</span>Active Threats (${threats.length})</h2>
  ${threatCards}
</div>

<!-- 4. INVESTIGATION FINDINGS -->
<div class="section page-break">
  <h2><span class="section-num">4</span>Behavioral Investigation Findings (${inv.length})</h2>
  ${invCards}
</div>

<!-- 5. AFFECTED USERS -->
<div class="section page-break">
  <h2><span class="section-num">5</span>Affected Users</h2>
  <table>
    <thead><tr><th>User / Account</th><th>Events</th><th>Alerts</th><th>Failed Logins</th><th>Source IPs</th></tr></thead>
    <tbody>${userRows}</tbody>
  </table>
</div>

<!-- 6. AFFECTED IPs -->
<div class="section">
  <h2><span class="section-num">6</span>Top Source IPs</h2>
  <table>
    <thead><tr><th>#</th><th>IP Address</th><th>Location</th><th>Risk</th><th>Events</th><th>Alerts</th><th>Failed Logins</th></tr></thead>
    <tbody>${ipRows || '<tr><td colspan="7" style="text-align:center;color:#94a3b8">No source IP data</td></tr>'}</tbody>
  </table>
</div>

<!-- 7. EVIDENCE TIMELINE -->
<div class="section page-break">
  <h2><span class="section-num">7</span>Evidence Timeline — Top ${evidenceEvents.length} Non-Low Events</h2>
  <div style="margin-top:4px">${timelineRows || '<div class="clean-card">✅ No medium/high/critical events to display.</div>'}</div>
</div>

<!-- 8. RECOMMENDATIONS -->
<div class="section page-break">
  <h2><span class="section-num">8</span>Recommendations</h2>
  ${recCards}
</div>

<!-- 9. CATEGORY BREAKDOWN -->
<div class="section">
  <h2><span class="section-num">9</span>Event Category Breakdown</h2>
  <table>
    <thead><tr><th>Category</th><th>Distribution</th><th>% of Total</th></tr></thead>
    <tbody>${catRows}</tbody>
  </table>
</div>

<!-- APPENDIX -->
<div class="section page-break">
  <h2>Appendix — Raw Event Log (Top ${appendixEvents.length} Non-Low Events)</h2>
  <p style="font-size:12px;color:#64748b;margin-bottom:12px">Only Medium, High, and Critical events are included. Low-severity events (routine web traffic, static assets) are excluded from this appendix to keep the report concise.</p>
  <table>
    <thead><tr><th>Timestamp</th><th>Severity</th><th>Type</th><th>Raw Log</th></tr></thead>
    <tbody>${appendixRows || '<tr><td colspan="4" style="text-align:center;color:#94a3b8">No events to display</td></tr>'}</tbody>
  </table>
</div>

<div class="footer">
  <span><span class="brand">CyberNyx</span> Log Analyzer — Auto-generated Security Report</span>
  <span>${timestamp}</span>
  <span>⚠️ Review with a qualified analyst before acting on findings.</span>
</div>

</body></html>`;

    // Use Blob URL — avoids popup blocker that kills document.write approach
    const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const w = window.open(url, '_blank');
    if (!w) {
      // Fallback: trigger download if popup was blocked
      const a = document.createElement('a');
      a.href = url;
      a.download = `cybernyx-report-${Date.now()}.html`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    }
    // Revoke after a delay so the new tab has time to load
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  };

  const handleFileUpload = async (event) => {
    const file = event.target.files[0];
    if (!file) return;
    setLoading(true);
    setUploadedFile(file);
    try {
      const text = await file.text();
      analyzeLogFile(text, file.name);
    } catch (error) {
      console.error('File analysis error:', error);
      alert(`Analysis error: ${error?.message || 'Unknown error. Check console for details.'}`);
    } finally {
      setLoading(false);
    }
  };

  const loadSampleFile = (type) => {
    setLoading(true);
    setTimeout(() => {
      try { analyzeLogFile(sampleLogs[type], `${type}_sample.log`); }
      catch (e) { console.error('Sample load error:', e); alert(`Analysis error: ${e?.message || 'Unknown error'}`); }
      finally { setLoading(false); }
    }, 500);
  };

  const analyzeLogFile = (logContent, fileName) => {
    const lines = logContent.split('\n').filter(line => line.trim());
    const results = [];
    const categoryStats = {};
    const timelineData = {};
    const uniqueIPs = new Set();

    lines.forEach((line, index) => {
      const categories = categorizeLogEntry(line);
      const eventType = detectEventType(line);
      const parameters = extractParameters(line);
      const threatLevel = assessThreatLevel(categories, line, parameters);
      
      if (parameters.sourceIP) uniqueIPs.add(parameters.sourceIP);
      if (parameters.destinationIP) uniqueIPs.add(parameters.destinationIP);
      
      categories.forEach(cat => { categoryStats[cat] = (categoryStats[cat] || 0) + 1; });
      const timeKey = parameters.timestamp?.split(' ')[0] || parameters.timestamp?.split(':')[0] || 'Unknown';
      if (!timelineData[timeKey]) timelineData[timeKey] = { count: 0, threats: 0 };
      timelineData[timeKey].count++;
      if (threatLevel === 'critical' || threatLevel === 'high') timelineData[timeKey].threats++;
      
      results.push({ lineNumber: index + 1, originalLog: line, categories, eventType, parameters, threatLevel, isAlert: threatLevel === 'critical' || threatLevel === 'high' });
    });

    const ipIntel = {};
    Array.from(uniqueIPs).forEach(ip => { ipIntel[ip] = generateIPIntelligence(ip); });

    // Build per-IP profiles for enriched Source IP panel
    const ipProfiles = {};
    results.forEach(r => {
      const ip = r.parameters.sourceIP;
      if (!ip) return;
      if (!ipProfiles[ip]) ipProfiles[ip] = { events: 0, users: new Set(), threats: 0, failedLogins: 0, criticalEvents: 0 };
      ipProfiles[ip].events++;
      if (r.parameters.user) ipProfiles[ip].users.add(r.parameters.user);
      if (r.isAlert) ipProfiles[ip].threats++;
      if (r.threatLevel === 'critical') ipProfiles[ip].criticalEvents++;
      if (r.categories.includes('Login Attempts') && /\b(fail|denied|invalid|bad.*password)\b/i.test(r.originalLog)) ipProfiles[ip].failedLogins++;
    });

    const threats = detectAdvancedThreats(results);
    let investigation = [];
    try { investigation = runInvestigationEngine(results); } catch (e) { console.error('Investigation engine error:', e); }
    const stats = {
      total: results.length,
      alerts: results.filter(r => r.isAlert).length,
      critical: results.filter(r => r.threatLevel === 'critical').length,
      high: results.filter(r => r.threatLevel === 'high').length,
      medium: results.filter(r => r.threatLevel === 'medium').length,
      low: results.filter(r => r.threatLevel === 'low').length,
      categoryBreakdown: categoryStats,
      uniqueIPs: uniqueIPs.size,
      fileName
    };

    const timeline = Object.entries(timelineData).map(([time, d]) => ({ time, count: d.count, threats: d.threats })).sort((a, b) => a.time.localeCompare(b.time));
    setAnalysis({ results, stats, threats, investigation, timeline, ipIntelligence: ipIntel, ipProfiles });
  };

  const getThreatLevelColor = (level) => {
    const colors = {
      critical: darkMode ? 'bg-red-100 text-red-800 border-red-400' : 'bg-red-100 text-red-800 border-red-400',
      high: darkMode ? 'bg-orange-100 text-orange-800 border-orange-400' : 'bg-orange-100 text-orange-800 border-orange-400',
      medium: darkMode ? 'bg-yellow-100 text-yellow-800 border-yellow-400' : 'bg-yellow-100 text-yellow-800 border-yellow-400',
      low: darkMode ? 'bg-green-100 text-green-800 border-green-400' : 'bg-green-100 text-green-800 border-green-400'
    };
    return colors[level] || colors.low;
  };

  const getCategoryColor = (category) => {
    const config = eventCategories[category];
    if (!config) return darkMode ? 'bg-gray-500' : 'bg-gray-400';
    const colors = { blue: 'bg-blue-500', cyan: 'bg-cyan-500', purple: 'bg-purple-500', yellow: 'bg-yellow-500', green: 'bg-green-500', red: 'bg-red-500', orange: 'bg-orange-500', indigo: 'bg-indigo-500', teal: 'bg-teal-500', pink: 'bg-pink-500', amber: 'bg-amber-500', rose: 'bg-rose-500' };
    return colors[config.color] || 'bg-gray-500';
  };

  // Score → Tailwind color helpers (component-scoped so all panels can use them)
  const scoreColor = (s) => s >= 90 ? 'text-red-400' : s >= 80 ? 'text-orange-400' : s >= 65 ? 'text-yellow-400' : s >= 50 ? 'text-blue-400' : 'text-gray-400';
  const scoreBg    = (s) => s >= 90 ? 'bg-red-500' : s >= 80 ? 'bg-orange-500' : s >= 65 ? 'bg-yellow-500' : s >= 50 ? 'bg-blue-500' : 'bg-gray-500';

  const toggleBookmark = (lineNumber) => {
    const newBookmarks = new Set(bookmarkedEvents);
    newBookmarks.has(lineNumber) ? newBookmarks.delete(lineNumber) : newBookmarks.add(lineNumber);
    setBookmarkedEvents(newBookmarks);
  };

  const getTopIPs = () => {
    if (!analysis) return [];
    const profiles = analysis.ipProfiles || {};
    // Build IP → investigation session map
    const ipInvMap = {};
    (analysis.investigation || []).forEach(s => {
      if (s.identifierType === 'ip') {
        if (!ipInvMap[s.identifier] || s.riskScore > (ipInvMap[s.identifier].riskScore || 0)) {
          ipInvMap[s.identifier] = s;
        }
      }
      (s.sessionEvents || []).forEach(e => {
        const ip = e.parameters?.sourceIP;
        if (ip && !ipInvMap[ip]) ipInvMap[ip] = s;
      });
    });
    return Object.entries(profiles)
      .sort(([, a], [, b]) => b.events - a.events)
      .slice(0, 8)
      .map(([ip, p]) => ({
        ip,
        count: p.events,
        users: p.users.size,
        threats: p.threats,
        failedLogins: p.failedLogins,
        critical: p.criticalEvents,
        intel: analysis.ipIntelligence?.[ip],
        investigation: ipInvMap[ip] || null
      }));
  };

  const filteredResults = analysis?.results.filter(result => {
    // Default: hide low-severity events unless user opts in
    if (showSuspiciousOnly && result.threatLevel === 'low') return false;

    let matchesCategory = true;
    if (filterCategory === 'alerts') matchesCategory = result.isAlert;
    else if (filterCategory === 'bookmarked') matchesCategory = bookmarkedEvents.has(result.lineNumber);
    else if (filterCategory !== 'all') matchesCategory = result.categories.includes(filterCategory);

    const matchesSeverity = filterSeverity === 'all' || result.threatLevel === filterSeverity;
    const matchesSearch = !searchQuery || result.originalLog.toLowerCase().includes(searchQuery.toLowerCase()) || Object.values(result.parameters).some(v => String(v).toLowerCase().includes(searchQuery.toLowerCase()));
    return matchesCategory && matchesSeverity && matchesSearch;
  }) || [];

  const clearFilters = () => { setFilterCategory('all'); setFilterSeverity('all'); setSearchQuery(''); };
  const getActiveFilterName = () => {
    if (filterCategory === 'all' && filterSeverity === 'all') return null;
    if (filterCategory !== 'all' && filterSeverity !== 'all') return `${filterCategory} + ${filterSeverity}`;
    if (filterCategory !== 'all') return filterCategory === 'alerts' ? 'Alerts Only' : filterCategory === 'bookmarked' ? 'Bookmarked' : filterCategory;
    return filterSeverity;
  };

  const exportResults = (format = 'csv') => {
    if (!analysis) return;
    if (format === 'csv') {
      const csv = [['Line', 'Event Type', 'Threat Level', 'Categories', 'Parameters', 'Original Log'].join(','), ...filteredResults.map(r => [r.lineNumber, r.eventType, r.threatLevel, r.categories.join(';'), Object.entries(r.parameters).map(([k,v]) => `${k}:${v}`).join(';'), `"${r.originalLog.replace(/"/g, '""')}"`].join(','))].join('\n');
      const blob = new Blob([csv], { type: 'text/csv' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `log_analysis_${Date.now()}.csv`;
      a.click();
    } else if (format === 'json') {
      const json = JSON.stringify({ analysis: filteredResults, stats: analysis.stats, threats: analysis.threats, ipIntelligence: analysis.ipIntelligence, timestamp: new Date().toISOString() }, null, 2);
      const blob = new Blob([json], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `log_analysis_${Date.now()}.json`;
      a.click();
    }
  };

  const COLORS = ['#3b82f6', '#ef4444', '#10b981', '#f59e0b', '#8b5cf6', '#ec4899', '#06b6d4', '#f43f5e'];

  return (
    <div className={`min-h-screen ${darkMode ? 'bg-slate-950 text-white' : 'bg-gray-50 text-gray-900'} p-6 relative overflow-hidden`}>
      {/* Animated Background - Dark Mode */}
      {darkMode && (
        <>
          <div className="absolute inset-0 bg-gradient-to-br from-blue-950 via-slate-900 to-purple-950"></div>
          
          {/* Flowing Waves */}
          <div className="absolute inset-0 opacity-30">
            <div className="absolute top-0 left-0 right-0 h-full">
              <div className="absolute top-1/4 left-0 right-0 h-32 bg-gradient-to-r from-blue-500/0 via-blue-500/40 to-blue-500/0 blur-2xl animate-wave"></div>
              <div className="absolute top-1/2 left-0 right-0 h-40 bg-gradient-to-r from-purple-500/0 via-purple-500/30 to-purple-500/0 blur-2xl animate-wave-slow"></div>
              <div className="absolute top-3/4 left-0 right-0 h-36 bg-gradient-to-r from-cyan-500/0 via-cyan-500/35 to-cyan-500/0 blur-2xl animate-wave-slower"></div>
            </div>
          </div>
          
          {/* Subtle orbs for depth */}
          <div className="absolute top-10 right-10 w-96 h-96 bg-blue-500/20 rounded-full blur-3xl animate-pulse"></div>
          <div className="absolute bottom-20 left-10 w-80 h-80 bg-purple-500/15 rounded-full blur-3xl animate-pulse" style={{animationDelay: '2s', animationDuration: '4s'}}></div>
        </>
      )}
      
      {/* Animated Background - Light Mode */}
      {!darkMode && (
        <>
          <div className="absolute inset-0 bg-gradient-to-br from-blue-50 via-teal-50 to-cyan-50"></div>
          
          {/* Flowing Waves */}
          <div className="absolute inset-0 opacity-40">
            <div className="absolute top-0 left-0 right-0 h-full">
              <div className="absolute top-1/4 left-0 right-0 h-32 bg-gradient-to-r from-teal-400/0 via-teal-400/30 to-teal-400/0 blur-2xl animate-wave"></div>
              <div className="absolute top-1/2 left-0 right-0 h-40 bg-gradient-to-r from-blue-400/0 via-blue-400/25 to-blue-400/0 blur-2xl animate-wave-slow"></div>
              <div className="absolute top-3/4 left-0 right-0 h-36 bg-gradient-to-r from-cyan-400/0 via-cyan-400/28 to-cyan-400/0 blur-2xl animate-wave-slower"></div>
            </div>
          </div>
          
          {/* Subtle orbs for depth */}
          <div className="absolute top-20 right-20 w-80 h-80 bg-teal-300/20 rounded-full blur-3xl animate-pulse"></div>
          <div className="absolute bottom-10 left-20 w-72 h-72 bg-blue-300/15 rounded-full blur-3xl animate-pulse" style={{animationDelay: '2s', animationDuration: '4s'}}></div>
        </>
      )}
      
      <style jsx>{`
        @keyframes wave {
          0%, 100% { transform: translateX(-50%) translateY(0); }
          50% { transform: translateX(50%) translateY(-20px); }
        }
        @keyframes wave-slow {
          0%, 100% { transform: translateX(50%) translateY(0); }
          50% { transform: translateX(-30%) translateY(15px); }
        }
        @keyframes wave-slower {
          0%, 100% { transform: translateX(-30%) translateY(0); }
          50% { transform: translateX(40%) translateY(-10px); }
        }
        .animate-wave {
          animation: wave 8s ease-in-out infinite;
        }
        .animate-wave-slow {
          animation: wave-slow 12s ease-in-out infinite;
        }
        .animate-wave-slower {
          animation: wave-slower 15s ease-in-out infinite;
        }
      `}</style>
      
      <div className="max-w-7xl mx-auto relative z-10">
        <div className="text-center mb-8">
          <div className="flex items-center justify-center gap-3 mb-4">
            <Shield className="w-12 h-12 text-blue-400" />
            <h1 className="text-4xl font-bold bg-gradient-to-r from-blue-400 to-cyan-400 bg-clip-text text-transparent">
              CyberNyx Log Analyzer
            </h1>
            <button onClick={() => setDarkMode(!darkMode)} className={`ml-4 p-2 rounded-lg transition-all ${darkMode ? 'bg-white/10 hover:bg-white/20' : 'bg-gray-800/10 hover:bg-gray-800/20'}`} title={darkMode ? 'Switch to Light Mode' : 'Switch to Dark Mode'}>
              {darkMode ? '☀️' : '🌙'}
            </button>
          </div>
          <p className={`text-lg font-medium ${darkMode ? 'text-gray-300' : 'text-gray-600'}`}>
            Detect threats faster. Analyze smarter. Stay secure.
          </p>
          <p className={`text-xs mt-2 ${darkMode ? 'text-gray-500' : 'text-gray-500'}`}>
            Developed by <span className="font-semibold text-blue-400">CyberNyx</span>
          </p>
        </div>

        <div className={`${darkMode ? 'bg-white/10 border-white/20' : 'bg-white border-gray-200 shadow-lg'} backdrop-blur-lg rounded-lg p-8 mb-6 border`}>
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Upload className="w-5 h-5 text-blue-400" />
              <h2 className={`text-xl font-semibold ${darkMode ? '' : 'text-gray-900'}`}>Analyze Logs</h2>
            </div>
            <div className={`flex gap-1 p-1 rounded-lg ${darkMode ? 'bg-white/10' : 'bg-gray-100'}`}>
              <button onClick={() => setInputMode('upload')} className={`px-4 py-1.5 rounded text-sm font-medium transition-all ${inputMode === 'upload' ? 'bg-blue-500 text-white shadow' : darkMode ? 'text-gray-400 hover:text-white' : 'text-gray-600 hover:text-gray-900'}`}>
                Upload File
              </button>
              <button onClick={() => setInputMode('paste')} className={`px-4 py-1.5 rounded text-sm font-medium transition-all ${inputMode === 'paste' ? 'bg-blue-500 text-white shadow' : darkMode ? 'text-gray-400 hover:text-white' : 'text-gray-600 hover:text-gray-900'}`}>
                Paste Logs
              </button>
            </div>
          </div>

          {inputMode === 'upload' ? (
            <label className={`flex flex-col items-center justify-center w-full h-48 border-2 border-dashed ${darkMode ? 'border-white/30 hover:border-blue-400' : 'border-gray-300 hover:border-blue-500'} rounded-lg cursor-pointer hover:bg-opacity-5 transition-all`}>
              <div className="flex flex-col items-center justify-center pt-5 pb-6">
                <FileText className="w-12 h-12 text-blue-400 mb-3" />
                <p className={`mb-2 text-sm ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                  <span className="font-semibold">Click to upload</span> or drag and drop
                </p>
                <p className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                  {uploadedFile ? `Selected: ${uploadedFile.name}` : 'Any log file (TXT, LOG, etc.)'}
                </p>
              </div>
              <input ref={fileInputRef} type="file" className="hidden" accept=".txt,.log,.csv" onChange={handleFileUpload} />
            </label>
          ) : (
            <div className="space-y-3">
              <textarea
                value={logText}
                onChange={e => setLogText(e.target.value)}
                placeholder={`Paste log content here...\n\nExample:\n2024-03-15 09:00:05 INFO user=alice GET /dashboard - Dashboard\n2024-03-15 09:00:35 INFO user=alice GET /api/data - API Request\n2024-03-15 09:01:05 INFO user=alice GET /api/data - API Request`}
                className={`w-full h-48 p-4 rounded-lg border font-mono text-xs resize-none focus:outline-none focus:ring-2 focus:ring-blue-500 ${darkMode ? 'bg-black/30 border-white/20 text-gray-300 placeholder-gray-600' : 'bg-gray-50 border-gray-300 text-gray-900 placeholder-gray-400'}`}
              />
              <button
                onClick={analyzeFromPaste}
                disabled={!logText.trim() || loading}
                className="w-full py-3 bg-blue-500 hover:bg-blue-600 disabled:opacity-40 disabled:cursor-not-allowed text-white font-semibold rounded-lg transition-all flex items-center justify-center gap-2"
              >
                <Activity className="w-4 h-4" />
                Analyze Logs
              </button>
            </div>
          )}

          {loading && (
            <div className={`mt-4 text-center ${darkMode ? 'text-blue-400' : 'text-blue-600'}`}>
              <Activity className="w-6 h-6 animate-spin inline-block mr-2" />
              Analyzing log file with advanced threat intelligence...
            </div>
          )}
          
          <div className="mt-6">
            <div className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'} mb-3`}>Or try a sample log file:</div>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <button onClick={() => loadSampleFile('webaccess')} className={`${darkMode ? 'bg-purple-500/10 hover:bg-purple-500/20 border-purple-500/40' : 'bg-purple-50 hover:bg-purple-100 border-purple-200'} border-2 rounded-lg p-4 text-left transition-all group`}>
                <div className="flex items-center gap-3">
                  <span className="text-3xl">🔍</span>
                  <div className="flex-1">
                    <div className={`font-semibold mb-1 ${darkMode ? 'text-purple-300' : 'text-purple-800'}`}>Web Access Log</div>
                    <p className={`text-xs ${darkMode ? 'text-purple-400' : 'text-purple-600'}`}>Automation + takeover demo</p>
                  </div>
                </div>
              </button>
              <button onClick={() => loadSampleFile('firewall')} className={`${darkMode ? 'bg-white/5 hover:bg-white/10 border-white/20' : 'bg-gray-50 hover:bg-gray-100 border-gray-200'} border rounded-lg p-4 text-left transition-all group`}>
                <div className="flex items-center gap-3">
                  <span className="text-3xl">🛡️</span>
                  <div className="flex-1">
                    <div className={`font-semibold mb-1 ${darkMode ? 'text-white' : 'text-gray-900'}`}>Firewall Logs</div>
                    <p className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>NetScreen with port scans</p>
                  </div>
                </div>
              </button>
              
              <button onClick={() => loadSampleFile('switch')} className={`${darkMode ? 'bg-white/5 hover:bg-white/10 border-white/20' : 'bg-gray-50 hover:bg-gray-100 border-gray-200'} border rounded-lg p-4 text-left transition-all group`}>
                <div className="flex items-center gap-3">
                  <span className="text-3xl">🌐</span>
                  <div className="flex-1">
                    <div className={`font-semibold mb-1 ${darkMode ? 'text-white' : 'text-gray-900'}`}>Switch Logs</div>
                    <p className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Cisco with brute force</p>
                  </div>
                </div>
              </button>
              
              <button onClick={() => loadSampleFile('system')} className={`${darkMode ? 'bg-white/5 hover:bg-white/10 border-white/20' : 'bg-gray-50 hover:bg-gray-100 border-gray-200'} border rounded-lg p-4 text-left transition-all group`}>
                <div className="flex items-center gap-3">
                  <span className="text-3xl">💻</span>
                  <div className="flex-1">
                    <div className={`font-semibold mb-1 ${darkMode ? 'text-white' : 'text-gray-900'}`}>System Logs</div>
                    <p className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Events & resource alerts</p>
                  </div>
                </div>
              </button>
            </div>
          </div>
        </div>

        {analysis && (
          <>
            {/* Statistics Dashboard */}
            {(() => {
              const inv = analysis.investigation || [];
              const affectedUsers = new Set(inv.filter(s => s.identifierType === 'user').map(s => s.identifier)).size;
              const allMitre = new Set();
              inv.forEach(s => s.findings.forEach(f => { if (f.mitre) allMitre.add(f.mitre.id); }));
              const criticalSessions = inv.filter(s => s.tier === 'critical').length;
              return (
                <>
                  {/* Investigation-focused metrics */}
                  <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-3">
                    <div className={`${darkMode ? 'bg-white/10 border-red-500/40' : 'bg-white border-red-300 shadow'} rounded-lg p-4 border`}>
                      <div className={`text-xs font-bold uppercase tracking-wider mb-1 ${darkMode ? 'text-red-400' : 'text-red-600'}`}>Confirmed Threats</div>
                      <div className="text-3xl font-bold text-red-400">{analysis.threats.length}</div>
                      <div className={`text-xs mt-1 ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>{analysis.stats.critical} critical events</div>
                    </div>
                    <div className={`${darkMode ? 'bg-white/10 border-orange-500/40' : 'bg-white border-orange-300 shadow'} rounded-lg p-4 border`}>
                      <div className={`text-xs font-bold uppercase tracking-wider mb-1 ${darkMode ? 'text-orange-400' : 'text-orange-600'}`}>Suspicious Sessions</div>
                      <div className="text-3xl font-bold text-orange-400">{inv.length}</div>
                      <div className={`text-xs mt-1 ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>{criticalSessions} critical tier</div>
                    </div>
                    <div className={`${darkMode ? 'bg-white/10 border-blue-500/40' : 'bg-white border-blue-300 shadow'} rounded-lg p-4 border`}>
                      <div className={`text-xs font-bold uppercase tracking-wider mb-1 ${darkMode ? 'text-blue-400' : 'text-blue-600'}`}>Affected Users</div>
                      <div className="text-3xl font-bold text-blue-400">{affectedUsers}</div>
                      <div className={`text-xs mt-1 ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>{analysis.stats.uniqueIPs} unique IPs</div>
                    </div>
                    <div className={`${darkMode ? 'bg-white/10 border-purple-500/40' : 'bg-white border-purple-300 shadow'} rounded-lg p-4 border`}>
                      <div className={`text-xs font-bold uppercase tracking-wider mb-1 ${darkMode ? 'text-purple-400' : 'text-purple-600'}`}>Unique MITRE</div>
                      <div className="text-3xl font-bold text-purple-400">{allMitre.size}</div>
                      <div className={`text-xs mt-1 font-mono truncate ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>{[...allMitre].slice(0, 3).join(' · ') || '—'}</div>
                    </div>
                  </div>
                  {/* Severity strip */}
                  <div className={`${darkMode ? 'bg-white/10 border-white/10' : 'bg-white border-gray-200 shadow'} rounded-lg px-5 py-3 border mb-6 flex items-center gap-6 flex-wrap`}>
                    {[['Critical', analysis.stats.critical, 'text-red-400'], ['High', analysis.stats.high, 'text-orange-400'], ['Medium', analysis.stats.medium, 'text-yellow-400'], ['Low', analysis.stats.low, 'text-green-400']].map(([label, val, cls]) => (
                      <div key={label} className="flex items-center gap-2">
                        <span className={`text-2xl font-bold tabular-nums ${cls}`}>{val.toLocaleString()}</span>
                        <span className={`text-xs ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>{label}</span>
                      </div>
                    ))}
                    <div className="flex-1 min-w-32">
                      <div className="flex gap-0.5 h-2 rounded overflow-hidden">
                        {analysis.stats.critical > 0 && <div style={{ flex: analysis.stats.critical }} className="bg-red-500" />}
                        {analysis.stats.high > 0 && <div style={{ flex: analysis.stats.high }} className="bg-orange-400" />}
                        {analysis.stats.medium > 0 && <div style={{ flex: analysis.stats.medium }} className="bg-yellow-400" />}
                        {analysis.stats.low > 0 && <div style={{ flex: analysis.stats.low }} className="bg-green-400" />}
                      </div>
                    </div>
                    <span className={`text-xs ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>{analysis.stats.total.toLocaleString()} total events</span>
                  </div>
                </>
              );
            })()}

            {/* Threat Intelligence Section */}
            {analysis.threats.length > 0 && (
              <div className={`${darkMode ? 'bg-red-900/20 border-red-500/50' : 'bg-red-50 border-red-200'} rounded-lg p-6 mb-6 border-2`}>
                <div className="flex items-center gap-2 mb-4">
                  <AlertTriangle className="w-6 h-6 text-red-400" />
                  <h2 className={`text-2xl font-bold ${darkMode ? 'text-red-400' : 'text-red-700'}`}>🚨 Active Threats Detected ({analysis.threats.length})</h2>
                </div>
                
                <div className="space-y-4">
                  {analysis.threats.map((threat, idx) => (
                    <div key={idx} className={`${darkMode ? 'bg-slate-900/70' : 'bg-white'} rounded-lg p-5 border-l-4 border-red-500`}>
                      <div className="flex items-start justify-between mb-3">
                        <div>
                          <h3 className={`text-xl font-bold ${darkMode ? 'text-white' : 'text-gray-900'} mb-1`}>{threat.type}</h3>
                          <span className={`px-2 py-1 rounded text-xs font-semibold ${getThreatLevelColor(threat.severity)}`}>{threat.severity.toUpperCase()}</span>
                        </div>
                      </div>
                      
                      <p className={`${darkMode ? 'text-gray-300' : 'text-gray-700'} mb-3`}>{threat.description}</p>
                      
                      <div className={`${darkMode ? 'bg-blue-900/30' : 'bg-blue-50'} rounded-lg p-3 mb-3`}>
                        <div className={`font-semibold ${darkMode ? 'text-cyan-300' : 'text-blue-700'} mb-2`}>💡 Recommendation:</div>
                        <p className={`${darkMode ? 'text-gray-300' : 'text-gray-700'} text-sm`}>{threat.recommendation}</p>
                      </div>
                      
                      {threat.mitigation && (
                        <div className={`${darkMode ? 'bg-green-900/30' : 'bg-green-50'} rounded-lg p-3`}>
                          <div className={`font-semibold ${darkMode ? 'text-green-300' : 'text-green-700'} mb-2 text-sm`}>🛡️ Mitigation Steps:</div>
                          <ul className="list-disc list-inside space-y-1">
                            {threat.mitigation.map((step, i) => (
                              <li key={i} className={`${darkMode ? 'text-gray-300' : 'text-gray-700'} text-sm`}>{step}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Investigation Findings */}
            {analysis.investigation && analysis.investigation.length > 0 && (() => {
              const inv = analysis.investigation;
              const critical = inv.filter(s => s.tier === 'critical');
              const review   = inv.filter(s => s.tier === 'review');
              const info     = inv.filter(s => s.tier === 'info');

              const SESSION_PREVIEW = 5;
              const visibleSessions = showAllSessions ? inv : inv.slice(0, SESSION_PREVIEW);
              const hiddenCount = inv.length - SESSION_PREVIEW;

              const sevDot = { critical: 'bg-red-500', high: 'bg-orange-400', medium: 'bg-yellow-400', low: 'bg-green-400' };

              const SessionCard = ({ session, idx }) => {
                const isExpanded = expandedSessions.has(idx);
                const toggleSession = () => {
                  const next = new Set(expandedSessions);
                  next.has(idx) ? next.delete(idx) : next.add(idx);
                  setExpandedSessions(next);
                };
                const topFinding = session.findings[0];
                const borderColor = session.tier === 'critical' ? 'border-red-500' : session.tier === 'review' ? 'border-orange-400' : 'border-yellow-400/60';

                return (
                  <div className={`${darkMode ? 'bg-slate-900/70' : 'bg-white'} rounded-lg border-l-4 overflow-hidden shadow-sm ${borderColor}`}>
                    {/* Collapsed header */}
                    <button onClick={toggleSession} className="w-full p-4 text-left hover:bg-white/5 transition-colors">
                      <div className="flex items-center justify-between gap-3">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap mb-1">
                            <span className={`text-xs font-semibold px-2 py-0.5 rounded shrink-0 ${darkMode ? 'bg-blue-500/20 text-blue-300' : 'bg-blue-100 text-blue-700'}`}>
                              {session.identifierType === 'user' ? '👤 User' : '🌐 IP'}
                            </span>
                            <span className={`font-mono font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>{session.identifier}</span>
                            {topFinding?.mitre && (
                              <span className={`text-xs font-mono px-1.5 py-0.5 rounded ${darkMode ? 'bg-purple-900/30 text-purple-400' : 'bg-purple-50 text-purple-600'}`}>
                                {topFinding.mitre.id}
                              </span>
                            )}
                            <span className={`text-xs ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>{session.totalEvents} events</span>
                          </div>
                          {/* One-line preview */}
                          {topFinding && (
                            <div className={`text-xs truncate ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                              {topFinding.icon} {topFinding.type} — {topFinding.detail}
                            </div>
                          )}
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          <div className={`text-xl font-bold tabular-nums ${scoreColor(session.riskScore)}`}>
                            {session.riskScore}<span className={`text-xs font-normal ${darkMode ? 'text-gray-600' : 'text-gray-400'}`}>/100</span>
                          </div>
                          {isExpanded ? <ChevronUp className="w-4 h-4 text-gray-400" /> : <ChevronDown className="w-4 h-4 text-gray-400" />}
                        </div>
                      </div>
                    </button>

                    {/* Animated expand */}
                    <div className={`transition-all duration-300 ease-in-out overflow-hidden ${isExpanded ? 'max-h-[3000px] opacity-100' : 'max-h-0 opacity-0'}`}>
                      <div className="px-5 pb-5 border-t border-white/10">

                        {/* Case Summary */}
                        <div className={`mt-4 mb-4 p-4 rounded-lg ${darkMode ? 'bg-blue-950/40 border border-blue-500/20' : 'bg-blue-50 border border-blue-200'}`}>
                          <div className={`text-xs font-bold tracking-widest mb-2 ${darkMode ? 'text-blue-400' : 'text-blue-600'}`}>ANALYST CASE SUMMARY</div>
                          <p className={`text-sm leading-relaxed ${darkMode ? 'text-gray-200' : 'text-gray-700'}`}>{session.caseSummary}</p>
                        </div>

                        {/* Investigation Timeline */}
                        {session.sessionEvents && session.sessionEvents.length > 0 && (
                          <div className="mb-5">
                            <div className={`text-xs font-bold tracking-widest mb-3 ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>INVESTIGATION TIMELINE</div>
                            <div className="relative">
                              {/* Vertical line */}
                              <div className={`absolute left-[15px] top-0 bottom-0 w-px ${darkMode ? 'bg-white/10' : 'bg-gray-200'}`} />
                              <div className="space-y-1">
                                {session.sessionEvents.map((ev, ei) => {
                                  const isRepeated = ei > 0 && session.sessionEvents[ei - 1].eventType === ev.eventType;
                                  // Group repeated events: show first 2, then summarize
                                  if (isRepeated) {
                                    const sameTypeAhead = session.sessionEvents.slice(ei).filter(e => e.eventType === ev.eventType);
                                    // Show ellipsis only once when 3+ consecutive same events
                                    const prevCount = session.sessionEvents.slice(0, ei).filter(e => e.eventType === ev.eventType).length;
                                    if (prevCount === 2) {
                                      const remaining = session.sessionEvents.slice(ei).filter(e => e.eventType === ev.eventType).length;
                                      return (
                                        <div key={ei} className="flex items-center gap-3 pl-8">
                                          <span className={`text-xs italic ${darkMode ? 'text-gray-600' : 'text-gray-400'}`}>
                                            ···  {remaining} more "{ev.eventType}" events
                                          </span>
                                        </div>
                                      );
                                    }
                                    if (prevCount > 2) return null;
                                  }
                                  return (
                                    <div key={ei} className="flex items-start gap-3">
                                      <div className={`w-[31px] shrink-0 flex justify-center pt-1.5`}>
                                        <div className={`w-2 h-2 rounded-full shrink-0 ${sevDot[ev.threatLevel] || 'bg-gray-400'}`} />
                                      </div>
                                      <div className={`flex-1 rounded p-2 text-xs ${darkMode ? 'bg-white/5 hover:bg-white/8' : 'bg-gray-50 hover:bg-gray-100'} transition-colors`}>
                                        <div className="flex items-center gap-2 flex-wrap">
                                          {ev.parameters.timestamp && <span className={`font-mono ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>{ev.parameters.timestamp}</span>}
                                          <span className={`font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>{ev.eventType}</span>
                                          {ev.parameters.user && <span className={`${darkMode ? 'text-blue-400' : 'text-blue-600'}`}>👤 {ev.parameters.user}</span>}
                                          {ev.parameters.sourceIP && <span className={`${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>{ev.parameters.sourceIP}</span>}
                                          {ev.parameters.url && <span className={`font-mono truncate max-w-xs ${darkMode ? 'text-cyan-400' : 'text-cyan-700'}`}>{ev.parameters.url}</span>}
                                        </div>
                                      </div>
                                    </div>
                                  );
                                })}
                                {session.totalEvents > 60 && (
                                  <div className={`pl-8 text-xs italic ${darkMode ? 'text-gray-600' : 'text-gray-400'}`}>
                                    + {session.totalEvents - 60} more events not shown
                                  </div>
                                )}
                              </div>
                            </div>
                          </div>
                        )}

                        {/* Behavior Sequence */}
                        {session.behaviorSequence.length > 0 && (
                          <div className="mb-4">
                            <div className={`text-xs font-semibold tracking-widest ${darkMode ? 'text-gray-500' : 'text-gray-400'} mb-2`}>BEHAVIOR SEQUENCE</div>
                            <div className="flex items-center gap-2 flex-wrap">
                              {session.behaviorSequence.map((step, i) => (
                                <React.Fragment key={i}>
                                  {i > 0 && <span className={`${darkMode ? 'text-gray-600' : 'text-gray-400'} text-sm`}>→</span>}
                                  <span className={`px-2 py-1 rounded text-xs font-medium ${
                                    step.count > 3
                                      ? darkMode ? 'bg-red-900/40 text-red-300 border border-red-500/40' : 'bg-red-100 text-red-700 border border-red-200'
                                      : darkMode ? 'bg-white/10 text-gray-300' : 'bg-gray-100 text-gray-700'
                                  }`}>
                                    {step.type}{step.count > 1 ? ` ×${step.count}` : ''}
                                  </span>
                                </React.Fragment>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Findings */}
                        <div className="space-y-3">
                          {session.findings.map((finding, fi) => (
                            <div key={fi} className={`rounded-lg p-4 ${
                              finding.confidence >= 88
                                ? darkMode ? 'bg-red-900/25 border border-red-500/30' : 'bg-red-50 border border-red-200'
                                : finding.confidence >= 65
                                  ? darkMode ? 'bg-orange-900/20 border border-orange-500/30' : 'bg-orange-50 border border-orange-200'
                                  : finding.confidence >= 50
                                    ? darkMode ? 'bg-blue-900/15 border border-blue-500/20' : 'bg-blue-50 border border-blue-200'
                                    : darkMode ? 'bg-white/5 border border-white/10' : 'bg-gray-50 border border-gray-200'
                            }`}>
                              <div className="flex items-start justify-between mb-2 gap-2 flex-wrap">
                                <div className="flex items-center gap-2 flex-wrap">
                                  <span className="text-lg">{finding.icon}</span>
                                  <span className={`font-bold text-sm ${darkMode ? 'text-white' : 'text-gray-900'}`}>{finding.type}</span>
                                  {finding.mitre && (
                                    <a href={`https://attack.mitre.org/techniques/${finding.mitre.id.replace('.', '/')}/`} target="_blank" rel="noopener noreferrer"
                                      className="text-xs font-mono px-2 py-0.5 rounded border border-purple-500/50 text-purple-400 bg-purple-900/20 hover:bg-purple-800/30 transition-colors">
                                      {finding.mitre.id}
                                    </a>
                                  )}
                                  {finding.mitre && (
                                    <span className={`text-xs px-2 py-0.5 rounded ${darkMode ? 'text-purple-300/70 bg-purple-900/10' : 'text-purple-600 bg-purple-50'}`}>
                                      {finding.mitre.tactic}
                                    </span>
                                  )}
                                </div>
                                <span className={`text-xs font-bold px-2 py-1 rounded shrink-0 text-white ${scoreBg(finding.confidence)}`}>{finding.confidence}%</span>
                              </div>
                              <p className={`text-sm mb-3 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>{finding.detail}</p>
                              {finding.evidence?.length > 0 && (
                                <ul className={`text-xs mb-3 space-y-1 pl-4 list-disc ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                                  {finding.evidence.map((e, ei) => <li key={ei}>{e}</li>)}
                                </ul>
                              )}
                              {finding.sparklineData && finding.sparklineData.length > 1 && (
                                <div className="mb-3">
                                  <div className={`text-xs font-semibold tracking-widest ${darkMode ? 'text-gray-500' : 'text-gray-400'} mb-1`}>REQUEST INTERVAL PATTERN</div>
                                  <div className={`rounded p-2 ${darkMode ? 'bg-black/30' : 'bg-white'}`}>
                                    <ResponsiveContainer width="100%" height={56}>
                                      <LineChart data={finding.sparklineData} margin={{ top: 4, right: 4, bottom: 4, left: 4 }}>
                                        <Line type="monotone" dataKey="interval" stroke={finding.confidence >= 88 ? '#ef4444' : '#f97316'} strokeWidth={2} dot={{ r: 3 }} />
                                        <Tooltip contentStyle={{ backgroundColor: darkMode ? '#1e293b' : '#fff', border: '1px solid #6366f1', borderRadius: '6px', fontSize: '11px' }}
                                          formatter={(v) => [`${v}s`, 'Interval']} labelFormatter={(l) => `Request #${l}`} />
                                      </LineChart>
                                    </ResponsiveContainer>
                                    <div className={`text-center text-xs mt-1 ${darkMode ? 'text-gray-600' : 'text-gray-400'}`}>Flat = automation · Spiky = human</div>
                                  </div>
                                </div>
                              )}
                              <div className="flex flex-wrap gap-2">
                                {finding.mitigations.map((m, mi) => (
                                  <span key={mi} className={`text-xs px-2 py-1 rounded ${darkMode ? 'bg-blue-900/30 text-blue-300 border border-blue-500/20' : 'bg-blue-50 text-blue-700 border border-blue-200'}`}>{m}</span>
                                ))}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>
                );
              };

              const TierGroup = ({ label, color, sessions, startIdx }) => {
                if (sessions.length === 0) return null;
                return (
                  <div className="mb-5">
                    <div className={`flex items-center gap-2 mb-3 pb-2 border-b ${darkMode ? 'border-white/10' : 'border-gray-200'}`}>
                      <span className={`text-xs font-bold px-3 py-1 rounded-full ${color}`}>{label}</span>
                      <span className={`text-xs ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>{sessions.length} session{sessions.length !== 1 ? 's' : ''}</span>
                    </div>
                    <div className="space-y-2">
                      {sessions.map((s, i) => <SessionCard key={startIdx + i} session={s} idx={inv.indexOf(s)} />)}
                    </div>
                  </div>
                );
              };

              // Filter visible sessions into tiers
              const visibleCritical = visibleSessions.filter(s => s.tier === 'critical');
              const visibleReview   = visibleSessions.filter(s => s.tier === 'review');
              const visibleInfo     = visibleSessions.filter(s => s.tier === 'info');

              return (
                <div className={`${darkMode ? 'bg-purple-900/20 border-purple-500/40' : 'bg-purple-50 border-purple-200'} rounded-lg p-6 mb-6 border-2`}>
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-3 flex-wrap">
                      <Search className="w-5 h-5 text-purple-400" />
                      <h2 className={`text-xl font-bold ${darkMode ? 'text-purple-400' : 'text-purple-700'}`}>
                        Behavioral Investigation
                      </h2>
                      <div className="flex gap-2">
                        {critical.length > 0 && <span className="text-xs font-bold px-2 py-0.5 rounded-full bg-red-500/20 text-red-400 border border-red-500/30">🚨 {critical.length} Critical</span>}
                        {review.length > 0 && <span className="text-xs font-bold px-2 py-0.5 rounded-full bg-orange-500/20 text-orange-400 border border-orange-500/30">⚠️ {review.length} Review</span>}
                        {info.length > 0 && <span className="text-xs font-bold px-2 py-0.5 rounded-full bg-blue-500/20 text-blue-400 border border-blue-500/30">ℹ️ {info.length} Info</span>}
                      </div>
                    </div>
                    <button onClick={() => setShowInvestigation(!showInvestigation)} className={`p-2 rounded ${darkMode ? 'bg-white/10 hover:bg-white/20' : 'bg-purple-100 hover:bg-purple-200'} transition-all`}>
                      {showInvestigation ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
                    </button>
                  </div>

                  {showInvestigation && (
                    <>
                      {/* Investigation Overview */}
                      {inv.length > 0 && (() => {
                        const topSession = inv[0];
                        const topFinding = topSession.findings[0];
                        const allMitreInv = [...new Set(inv.flatMap(s => s.findings.map(f => f.mitre?.id).filter(Boolean)))];
                        const affectedUserIds = [...new Set(inv.filter(s => s.identifierType === 'user').map(s => s.identifier))];
                        // Time range: min/max timestamp across all session events
                        const allTs = inv.flatMap(s => (s.sessionEvents || []).map(e => e.parameters.timestamp).filter(Boolean));
                        const timeRange = allTs.length >= 2 ? `${allTs[0]} – ${allTs[allTs.length - 1]}` : null;

                        return (
                          <div className={`mb-5 p-4 rounded-lg ${darkMode ? 'bg-slate-900/60 border border-white/10' : 'bg-white border border-gray-200 shadow-sm'}`}>
                            <div className={`text-xs font-bold tracking-widest mb-3 ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>INVESTIGATION OVERVIEW</div>
                            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
                              <div>
                                <div className={`text-xs ${darkMode ? 'text-gray-500' : 'text-gray-400'} mb-0.5`}>Attack Type</div>
                                <div className={`text-sm font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>{topFinding?.type || '—'}</div>
                              </div>
                              <div>
                                <div className={`text-xs ${darkMode ? 'text-gray-500' : 'text-gray-400'} mb-0.5`}>Affected Users</div>
                                <div className={`text-sm font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                                  {affectedUserIds.length > 0 ? (
                                    <span title={affectedUserIds.join(', ')}>{affectedUserIds.length} user{affectedUserIds.length !== 1 ? 's' : ''}</span>
                                  ) : '—'}
                                </div>
                              </div>
                              <div>
                                <div className={`text-xs ${darkMode ? 'text-gray-500' : 'text-gray-400'} mb-0.5`}>MITRE Techniques</div>
                                <div className="flex flex-wrap gap-1">
                                  {allMitreInv.slice(0, 4).map(id => (
                                    <span key={id} className={`text-xs font-mono px-1.5 py-0.5 rounded ${darkMode ? 'bg-purple-900/30 text-purple-400' : 'bg-purple-50 text-purple-600'}`}>{id}</span>
                                  ))}
                                  {allMitreInv.length > 4 && <span className={`text-xs ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>+{allMitreInv.length - 4}</span>}
                                  {allMitreInv.length === 0 && <span className={`text-xs ${darkMode ? 'text-gray-600' : 'text-gray-400'}`}>—</span>}
                                </div>
                              </div>
                              <div>
                                <div className={`text-xs ${darkMode ? 'text-gray-500' : 'text-gray-400'} mb-0.5`}>Observed</div>
                                <div className={`text-xs font-mono ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>{timeRange || '—'}</div>
                              </div>
                              <div>
                                <div className={`text-xs ${darkMode ? 'text-gray-500' : 'text-gray-400'} mb-0.5`}>Top Confidence</div>
                                <div className={`text-lg font-bold ${scoreColor(topSession.riskScore)}`}>
                                  {topSession.riskScore}<span className={`text-xs font-normal ${darkMode ? 'text-gray-600' : 'text-gray-400'}`}>/100</span>
                                </div>
                              </div>
                            </div>
                          </div>
                        );
                      })()}

                      <TierGroup label="🚨 Critical Investigations" color="bg-red-500/20 text-red-400 border border-red-500/30" sessions={visibleCritical} startIdx={0} />
                      <TierGroup label="⚠️ Needs Review" color="bg-orange-500/20 text-orange-400 border border-orange-500/30" sessions={visibleReview} startIdx={visibleCritical.length} />
                      <TierGroup label="ℹ️ Informational" color="bg-blue-500/20 text-blue-400 border border-blue-500/30" sessions={visibleInfo} startIdx={visibleCritical.length + visibleReview.length} />

                      {inv.length > SESSION_PREVIEW && (
                        <button
                          onClick={() => setShowAllSessions(s => !s)}
                          className={`mt-3 w-full py-2 rounded-lg text-sm font-semibold transition-all ${darkMode ? 'bg-white/5 hover:bg-white/10 text-gray-300 border border-white/10' : 'bg-white hover:bg-gray-50 text-gray-600 border border-gray-200'}`}
                        >
                          {showAllSessions ? `↑ Show top ${SESSION_PREVIEW} only` : `↓ Show ${hiddenCount} more session${hiddenCount !== 1 ? 's' : ''} (lower confidence)`}
                        </button>
                      )}
                    </>
                  )}
                </div>
              );
            })()}

            {/* Charts & Top IPs Section */}
            {showCharts && (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
                {/* Activity Timeline */}
                <div className={`${darkMode ? 'bg-white/10 border-white/20' : 'bg-white border-gray-200 shadow-lg'} rounded-lg p-6 border`}>
                  <h3 className={`text-lg font-semibold mb-1 flex items-center gap-2 ${darkMode ? '' : 'text-gray-900'}`}>
                    <Activity className="w-5 h-5 text-blue-400" />
                    Activity Timeline
                  </h3>
                  <p className={`text-xs mb-4 ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>Events by time period — spikes indicate bursts of activity</p>
                  <ResponsiveContainer width="100%" height={220}>
                    <BarChart data={analysis.timeline} margin={{ top: 4, right: 8, bottom: 20, left: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke={darkMode ? '#334155' : '#e2e8f0'} />
                      <XAxis dataKey="time" tick={{ fontSize: 10, fill: darkMode ? '#94a3b8' : '#64748b' }} angle={-35} textAnchor="end" interval="preserveStartEnd" />
                      <YAxis tick={{ fontSize: 10, fill: darkMode ? '#94a3b8' : '#64748b' }} />
                      <Tooltip
                        contentStyle={{ backgroundColor: darkMode ? '#1e293b' : '#ffffff', border: '1px solid #3b82f6', borderRadius: '8px', fontSize: '12px' }}
                        labelStyle={{ color: darkMode ? '#e5e7eb' : '#1e293b', fontWeight: 600 }}
                      />
                      <Bar dataKey="count" name="Total Events" fill={darkMode ? '#334155' : '#cbd5e1'} radius={[2, 2, 0, 0]} />
                      <Bar dataKey="threats" name="Threats (Critical/High)" fill="#ef4444" radius={[2, 2, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                  <div className="flex gap-5 mt-2">
                    <span className="flex items-center gap-1.5 text-xs text-gray-400"><span className="w-3 h-3 rounded-sm inline-block" style={{ background: darkMode ? '#334155' : '#cbd5e1' }} />Total events</span>
                    <span className="flex items-center gap-1.5 text-xs text-red-400"><span className="w-3 h-3 rounded-sm inline-block bg-red-500" />Threats (Critical + High)</span>
                  </div>
                </div>

                {/* Top Source IPs */}
                <div className={`${darkMode ? 'bg-white/10 border-white/20' : 'bg-white border-gray-200 shadow-lg'} rounded-lg p-6 border`}>
                  <h3 className={`text-lg font-semibold mb-4 flex items-center gap-2 ${darkMode ? '' : 'text-gray-900'}`}>
                    <MapPin className="w-5 h-5 text-red-400" />
                    Top Source IPs
                  </h3>
                  <div className="space-y-2">
                    {getTopIPs().map((item, i) => {
                      const riskColor = item.intel?.risk === 'High' ? 'text-red-400' : item.intel?.risk === 'Medium' ? 'text-yellow-400' : 'text-green-400';
                      const inv = item.investigation;
                      const hasInv = !!inv;
                      const rowBg = item.critical > 0 || hasInv
                        ? (darkMode ? 'bg-red-900/15 border border-red-500/20' : 'bg-red-50 border border-red-200')
                        : (darkMode ? 'bg-white/5 border border-white/5' : 'bg-gray-50 border border-gray-100');
                      return (
                        <div key={i} className={`${rowBg} rounded p-3 transition-all`}>
                          <div className="flex justify-between items-start mb-2">
                            <div>
                              <div className={`font-mono font-semibold text-sm ${darkMode ? 'text-white' : 'text-gray-900'}`}>{item.ip}</div>
                              {item.intel && (
                                <div className={`text-xs ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>
                                  {item.intel.country} · {item.intel.isp}
                                </div>
                              )}
                            </div>
                            <div className="text-right shrink-0 ml-3">
                              <div className={`text-sm font-bold text-blue-400`}>{item.count.toLocaleString()} events</div>
                              {item.intel && <div className={`text-xs font-semibold ${riskColor}`}>{item.intel.risk} Risk</div>}
                            </div>
                          </div>
                          <div className="flex gap-2 flex-wrap">
                            {item.users > 0 && <span className={`text-xs px-2 py-0.5 rounded ${darkMode ? 'bg-blue-900/40 text-blue-300' : 'bg-blue-100 text-blue-700'}`}>👤 {item.users} user{item.users !== 1 ? 's' : ''}</span>}
                            {item.threats > 0 && <span className={`text-xs px-2 py-0.5 rounded ${darkMode ? 'bg-orange-900/40 text-orange-300' : 'bg-orange-100 text-orange-700'}`}>⚠️ {item.threats} alerts</span>}
                            {item.failedLogins > 0 && <span className={`text-xs px-2 py-0.5 rounded ${darkMode ? 'bg-red-900/40 text-red-300' : 'bg-red-100 text-red-700'}`}>🔑 {item.failedLogins} failed logins</span>}
                            {item.critical > 0 && <span className="text-xs px-2 py-0.5 rounded bg-red-600 text-white font-semibold">🚨 {item.critical} critical</span>}
                          </div>
                          {/* Investigation link — why you care */}
                          {hasInv && (
                            <div className={`mt-2 pt-2 border-t ${darkMode ? 'border-white/10' : 'border-gray-200'}`}>
                              <div className="flex items-center justify-between gap-2">
                                <span className={`text-xs font-semibold ${darkMode ? 'text-orange-300' : 'text-orange-700'}`}>
                                  🔎 {inv.findings[0]?.type || 'Suspicious behavior'}
                                </span>
                                <span className={`text-xs font-bold tabular-nums ${scoreColor(inv.riskScore)}`}>{inv.riskScore}/100</span>
                              </div>
                              {inv.findings[0]?.mitre && (
                                <span className={`text-xs font-mono ${darkMode ? 'text-purple-400' : 'text-purple-600'}`}>{inv.findings[0].mitre.id} · {inv.findings[0].mitre.tactic}</span>
                              )}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            )}

            {/* Category Breakdown */}
            <div className={`${darkMode ? 'bg-white/10 border-white/20' : 'bg-white border-gray-200 shadow-lg'} rounded-lg p-6 mb-6 border`}>
              <div className="flex items-center gap-2 mb-4">
                <Activity className="w-5 h-5 text-blue-400" />
                <h3 className={`text-lg font-semibold ${darkMode ? '' : 'text-gray-900'}`}>Event Categories</h3>
              </div>
              
              <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
                {Object.entries(analysis.stats.categoryBreakdown).sort(([,a], [,b]) => b - a).map(([category, count]) => {
                  const config = eventCategories[category];
                  return (
                    <div key={category} className={`${darkMode ? 'bg-white/5 border-white/10' : 'bg-gray-50 border-gray-200'} rounded-lg p-3 border hover:bg-opacity-80 transition-all`}>
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-xl">{config?.icon || '📋'}</span>
                        <span className={`text-xs font-medium truncate ${darkMode ? '' : 'text-gray-900'}`}>{category}</span>
                      </div>
                      <div className="text-2xl font-bold text-blue-400">{count}</div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Filters, Search, and Event Log */}
            <div className={`${darkMode ? 'bg-white/10 border-white/20' : 'bg-white border-gray-200 shadow-lg'} rounded-lg p-4 mb-4 border`}>
              <div className="flex flex-col md:flex-row gap-4 items-start md:items-center justify-between">
                <div className="flex flex-col md:flex-row items-start md:items-center gap-3 flex-1 flex-wrap">
                  <div className="flex items-center gap-2">
                    <Filter className="w-5 h-5 text-blue-400" />
                    <select value={filterCategory} onChange={(e) => setFilterCategory(e.target.value)} className={`${darkMode ? 'bg-white/5 border-white/20 text-white' : 'bg-gray-50 border-gray-300 text-gray-900'} border rounded px-3 py-2 text-sm`}>
                      <option value="all">All Events ({analysis.results.length})</option>
                      <option value="alerts">⚠️ Alerts Only ({analysis.stats.alerts})</option>
                      <option value="bookmarked">🔖 Bookmarked ({bookmarkedEvents.size})</option>
                      <option disabled>────────────────</option>
                      <option disabled>📊 Filter by Category:</option>
                      {Object.entries(analysis.stats.categoryBreakdown).sort(([,a], [,b]) => b - a).map(([cat, count]) => (
                        <option key={cat} value={cat}>{eventCategories[cat]?.icon} {cat} ({count})</option>
                      ))}
                    </select>
                  </div>

                  <div className="flex items-center gap-2">
                    <select value={filterSeverity} onChange={(e) => setFilterSeverity(e.target.value)} className={`${darkMode ? 'bg-white/5 border-white/20 text-white' : 'bg-gray-50 border-gray-300 text-gray-900'} border rounded px-3 py-2 text-sm`}>
                      <option value="all">All Severity</option>
                      <option value="critical">🔴 Critical ({analysis.stats.critical})</option>
                      <option value="high">🟠 High ({analysis.stats.high})</option>
                      <option value="medium">🟡 Medium ({analysis.stats.medium})</option>
                      <option value="low">🟢 Low ({analysis.stats.low})</option>
                    </select>
                  </div>

                  <div className="flex items-center gap-2 flex-1 max-w-sm">
                    <Search className="w-4 h-4 text-blue-400 shrink-0" />
                    <input type="text" placeholder="Search logs…" value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} className={`${darkMode ? 'bg-white/5 border-white/20 text-white placeholder-gray-400' : 'bg-gray-50 border-gray-300 text-gray-900 placeholder-gray-500'} border rounded px-3 py-2 text-sm flex-1`} />
                  </div>

                  {/* Suspicious-only toggle */}
                  <button
                    onClick={() => setShowSuspiciousOnly(v => !v)}
                    className={`flex items-center gap-2 px-3 py-2 rounded text-sm font-semibold border transition-all ${showSuspiciousOnly ? 'bg-orange-500/20 border-orange-500/50 text-orange-400' : (darkMode ? 'bg-white/5 border-white/20 text-gray-400' : 'bg-gray-100 border-gray-300 text-gray-600')}`}
                  >
                    {showSuspiciousOnly ? <AlertTriangle className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    {showSuspiciousOnly ? 'Suspicious Only' : 'All Events'}
                  </button>

                  {getActiveFilterName() && (
                    <div className="flex items-center gap-2">
                      <span className="px-3 py-1 bg-blue-500 text-white rounded-full text-sm font-medium">{getActiveFilterName()}</span>
                      <button onClick={clearFilters} className="px-3 py-1 bg-red-500/20 hover:bg-red-500/30 border border-red-500/50 text-red-400 rounded-full text-sm transition-all">Clear</button>
                    </div>
                  )}
                </div>

                <div className="flex gap-2 shrink-0">
                  <button onClick={() => setShowCharts(!showCharts)} className="flex items-center gap-1 bg-purple-500/20 hover:bg-purple-500/30 border border-purple-500/50 rounded px-3 py-2 text-sm transition-all">
                    {showCharts ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    Charts
                  </button>
                  <button onClick={() => exportResults('csv')} className="flex items-center gap-1 bg-green-500/20 hover:bg-green-500/30 border border-green-500/50 rounded px-3 py-2 text-sm transition-all">
                    <Download className="w-4 h-4" />CSV
                  </button>
                  <button onClick={() => exportResults('json')} className="flex items-center gap-1 bg-blue-500/20 hover:bg-blue-500/30 border border-blue-500/50 rounded px-3 py-2 text-sm transition-all">
                    <Download className="w-4 h-4" />JSON
                  </button>
                  <button onClick={generateReport} className="flex items-center gap-1 bg-red-500/20 hover:bg-red-500/30 border border-red-500/50 text-red-400 rounded px-3 py-2 text-sm font-semibold transition-all">
                    <FileText className="w-4 h-4" />PDF
                  </button>
                </div>
              </div>

              <div className={`mt-2 text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                Showing {filteredResults.length} of {analysis.results.length} events
                {showSuspiciousOnly && analysis.stats.low > 0 && (
                  <span className={`ml-2 ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>
                    · {analysis.stats.low.toLocaleString()} low-severity events hidden
                  </span>
                )}
              </div>
            </div>

            {/* Event List */}
            <div className="space-y-3">
              {filteredResults.map((result) => (
                <div key={result.lineNumber} className={`${darkMode ? 'bg-white/10 border-white/20' : 'bg-white border-gray-200 shadow'} backdrop-blur-lg rounded-lg p-4 border-2 ${result.isAlert ? (darkMode ? 'border-orange-500/50' : 'border-orange-400') : ''} transition-all`}>
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-3 flex-wrap">
                      <span className={`${darkMode ? 'text-gray-400' : 'text-gray-500'} text-sm font-mono`}>#{result.lineNumber}</span>
                      <span className={`px-2 py-1 rounded text-xs font-semibold border ${getThreatLevelColor(result.threatLevel)}`}>{result.threatLevel.toUpperCase()}</span>
                      {result.parameters.timestamp && (
                        <span className={`${darkMode ? 'text-gray-400' : 'text-gray-500'} text-xs flex items-center gap-1`}>
                          <Clock className="w-3 h-3" />
                          {result.parameters.timestamp}
                        </span>
                      )}
                      <span className={`${darkMode ? 'text-cyan-400' : 'text-blue-600'} text-sm font-medium`}>{result.eventType}</span>
                    </div>
                    
                    <div className="flex items-center gap-2">
                      {result.isAlert && <AlertTriangle className="w-5 h-5 text-orange-400 flex-shrink-0" />}
                      <button onClick={() => toggleBookmark(result.lineNumber)} className={`p-1 rounded transition-colors ${bookmarkedEvents.has(result.lineNumber) ? 'text-yellow-400' : darkMode ? 'text-gray-400 hover:text-yellow-400' : 'text-gray-500 hover:text-yellow-500'}`}>
                        <BookmarkPlus className="w-5 h-5" />
                      </button>
                      <button onClick={() => setExpandedEvent(expandedEvent === result.lineNumber ? null : result.lineNumber)} className={`p-1 ${darkMode ? 'text-gray-400 hover:text-white' : 'text-gray-500 hover:text-gray-900'} transition-colors`}>
                        {expandedEvent === result.lineNumber ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
                      </button>
                    </div>
                  </div>
                  
                  <div className="mb-3 flex flex-wrap gap-2">
                    {result.categories.map((category, idx) => (
                      <span key={idx} className={`px-3 py-1 rounded text-xs font-semibold text-white ${getCategoryColor(category)}`}>
                        {eventCategories[category]?.icon} {category}
                      </span>
                    ))}
                  </div>
                  
                  <div className={`${darkMode ? 'bg-black/30' : 'bg-gray-100'} rounded p-3 mb-3 font-mono text-xs ${darkMode ? 'text-gray-300' : 'text-gray-800'} overflow-x-auto`}>
                    {result.originalLog}
                  </div>
                  
                  {expandedEvent === result.lineNumber && (
                    <div className="mt-3 space-y-3">
                      {Object.keys(result.parameters).length > 0 && (
                        <div>
                          <div className={`text-sm font-semibold ${darkMode ? 'text-gray-400' : 'text-gray-700'} mb-2`}>Extracted Parameters:</div>
                          <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                            {Object.entries(result.parameters).map(([key, value]) => (
                              <div key={key} className={`${darkMode ? 'bg-white/5' : 'bg-gray-50'} rounded px-3 py-2`}>
                                <div className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-600'} capitalize`}>{key}</div>
                                <div className={`text-sm font-semibold ${darkMode ? 'text-white' : 'text-gray-900'} truncate`}>{value}</div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                      
                      {(result.parameters.sourceIP || result.parameters.destinationIP) && (
                        <div>
                          <div className={`text-sm font-semibold ${darkMode ? 'text-gray-400' : 'text-gray-700'} mb-2 flex items-center gap-2`}>
                            <Globe className="w-4 h-4" />
                            IP Intelligence:
                          </div>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                            {result.parameters.sourceIP && analysis.ipIntelligence[result.parameters.sourceIP] && (
                              <div className={`${darkMode ? 'bg-blue-900/30' : 'bg-blue-50'} rounded-lg p-3`}>
                                <div className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-600'} mb-1`}>Source IP: {result.parameters.sourceIP}</div>
                                <div className="grid grid-cols-2 gap-2 text-xs">
                                  <div><span className={darkMode ? 'text-gray-400' : 'text-gray-600'}>Country:</span> <span className={darkMode ? 'text-white' : 'text-gray-900'}>{analysis.ipIntelligence[result.parameters.sourceIP].country}</span></div>
                                  <div><span className={darkMode ? 'text-gray-400' : 'text-gray-600'}>City:</span> <span className={darkMode ? 'text-white' : 'text-gray-900'}>{analysis.ipIntelligence[result.parameters.sourceIP].city}</span></div>
                                  <div><span className={darkMode ? 'text-gray-400' : 'text-gray-600'}>ISP:</span> <span className={darkMode ? 'text-white' : 'text-gray-900'}>{analysis.ipIntelligence[result.parameters.sourceIP].isp}</span></div>
                                  <div><span className={darkMode ? 'text-gray-400' : 'text-gray-600'}>Risk:</span> <span className={`ml-2 font-semibold ${analysis.ipIntelligence[result.parameters.sourceIP].risk === 'High' ? 'text-red-400' : analysis.ipIntelligence[result.parameters.sourceIP].risk === 'Medium' ? 'text-yellow-400' : 'text-green-400'}`}>{analysis.ipIntelligence[result.parameters.sourceIP].risk}</span></div>
                                </div>
                              </div>
                            )}
                            {result.parameters.destinationIP && analysis.ipIntelligence[result.parameters.destinationIP] && (
                              <div className={`${darkMode ? 'bg-purple-900/30' : 'bg-purple-50'} rounded-lg p-3`}>
                                <div className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-600'} mb-1`}>Destination IP: {result.parameters.destinationIP}</div>
                                <div className="grid grid-cols-2 gap-2 text-xs">
                                  <div><span className={darkMode ? 'text-gray-400' : 'text-gray-600'}>Country:</span> <span className={darkMode ? 'text-white' : 'text-gray-900'}>{analysis.ipIntelligence[result.parameters.destinationIP].country}</span></div>
                                  <div><span className={darkMode ? 'text-gray-400' : 'text-gray-600'}>City:</span> <span className={darkMode ? 'text-white' : 'text-gray-900'}>{analysis.ipIntelligence[result.parameters.destinationIP].city}</span></div>
                                  <div><span className={darkMode ? 'text-gray-400' : 'text-gray-600'}>ISP:</span> <span className={darkMode ? 'text-white' : 'text-gray-900'}>{analysis.ipIntelligence[result.parameters.destinationIP].isp}</span></div>
                                  <div><span className={darkMode ? 'text-gray-400' : 'text-gray-600'}>Type:</span> <span className={darkMode ? 'text-white' : 'text-gray-900'}>{analysis.ipIntelligence[result.parameters.destinationIP].type}</span></div>
                                </div>
                              </div>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </>
        )}
      </div>
    </div>
  );
};

export default LogAnalyzer;