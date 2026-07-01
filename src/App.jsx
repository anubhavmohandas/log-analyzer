import React, { useState, useRef } from 'react';
import { Shield, AlertTriangle, FileText, Upload, Search, Filter, Download, Activity, Clock, Globe, BookmarkPlus, ChevronDown, ChevronUp, MapPin, Eye, EyeOff } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';

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
  const [collapsedSessions, setCollapsedSessions] = useState(new Set());
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

  const eventCategories = {
    'Login Attempts': { patterns: [/login|logon|authentication|signin|sign-in|auth/i, /failed.*password|invalid.*credentials|auth.*fail/i, /successful.*login|logged in|authentication.*success/i, /ssh|telnet|rdp|ftp.*login/i], icon: '🔐', color: 'blue' },
    'Network Changes': { patterns: [/interface.*up|interface.*down|link.*up|link.*down/i, /route.*add|route.*del|routing.*change/i, /vlan.*config|port.*config|switch.*config/i, /network.*change|topology.*change/i], icon: '🌐', color: 'cyan' },
    'Firewall Actions': { patterns: [/deny|drop|block|reject|discard/i, /permit|allow|accept|pass/i, /firewall.*rule|acl|access.*list/i, /src=|dst=|proto=/i], icon: '🛡️', color: 'purple' },
    'Configuration Changes': { patterns: [/config.*change|configuration|configured from/i, /policy.*change|rule.*change|setting.*change/i, /admin|administrator|root|sudo/i, /modify|update|edit.*config/i], icon: '⚙️', color: 'yellow' },
    'System Events': { patterns: [/start|started|stop|stopped|restart|reboot/i, /service.*up|service.*down|daemon/i, /system.*error|kernel|crash|panic/i, /job.*start|job.*end|process/i], icon: '💻', color: 'green' },
    'Security Alerts': { patterns: [/attack|intrusion|breach|exploit|vulnerability/i, /malware|virus|trojan|backdoor|ransomware/i, /suspicious|anomaly|unusual|unauthorized/i, /scan|probe|flood|ddos/i], icon: '🚨', color: 'red' },
    'Access Control': { patterns: [/permission|privilege|access.*denied|forbidden/i, /unauthorized|unauthenticated/i, /role.*change|group.*add|user.*add/i, /sudo|su|privilege.*escalation/i], icon: '🔒', color: 'orange' },
    'Data Transfer': { patterns: [/transfer|upload|download|file.*transfer/i, /bytes.*sent|bytes.*received|traffic/i, /ftp|sftp|scp|http.*post/i, /data.*sent|data.*received/i], icon: '📡', color: 'indigo' },
    'Port Activity': { patterns: [/port.*\d+|destination.*port|source.*port/i, /22|23|80|443|3389|445|3306|1433|5432/, /ssh.*port|rdp.*port|http.*port/i, /port.*scan|port.*probe/i], icon: '🔌', color: 'teal' },
    'Session Management': { patterns: [/session.*start|session.*end|session.*expire/i, /connection.*establish|connection.*close/i, /timeout|idle|disconnect/i, /keepalive|heartbeat/i], icon: '🔗', color: 'pink' },
    'Resource Alerts': { patterns: [/cpu|memory|disk|ram/i, /threshold|usage|capacity/i, /resource|performance/i, /overload|exhaustion/i], icon: '⚡', color: 'amber' },
    'Error Events': { patterns: [/error|fail|failure|fatal/i, /exception|abort|crash/i, /timeout|unreachable/i, /corrupt|invalid/i], icon: '❌', color: 'rose' }
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
    
    const userPattern = /(?:userId|user|username|account)[=:\s"']+([^"'\s]+)/i;
    const userMatch = logLine.match(userPattern);
    if (userMatch) params.user = userMatch[1];
    
    const interfacePattern = /(?:interface|int)[:\s]+(\S+)/i;
    const interfaceMatch = logLine.match(interfacePattern);
    if (interfaceMatch) params.interface = interfaceMatch[1];
    
    return params;
  };

  const assessThreatLevel = (categories, logLine, params) => {
    const highRiskCategories = ['Security Alerts', 'Access Control', 'Error Events'];
    const mediumRiskCategories = ['Login Attempts', 'Firewall Actions', 'Port Activity'];
    const hasHighRisk = categories.some(cat => highRiskCategories.includes(cat));
    const hasMediumRisk = categories.some(cat => mediumRiskCategories.includes(cat));
    
    if (/fail|deny|reject|block|error|unauthorized|critical/i.test(logLine)) {
      if (hasHighRisk || /critical|attack|breach|exploit/i.test(logLine)) return 'critical';
      return 'high';
    }
    if (hasHighRisk) return 'high';
    if (hasMediumRisk) return 'medium';
    return 'low';
  };

  const detectAdvancedThreats = (events) => {
    const threats = [];
    const ipFailures = {};
    const portScans = {};

    events.forEach((event, idx) => {
      const ip = event.parameters.sourceIP || 'unknown';

      if (event.categories.includes('Login Attempts') && /fail|denied/i.test(event.originalLog)) {
        ipFailures[ip] = ipFailures[ip] || [];
        ipFailures[ip].push(idx);

        if (ipFailures[ip].length >= 3) {
          threats.push({
            type: 'Brute Force Attack',
            severity: 'critical',
            description: `${ipFailures[ip].length} failed login attempts from IP: ${ip}`,
            recommendation: 'Block this IP immediately using firewall rules. Review authentication logs for successful logins. Implement account lockout policies.',
            mitigation: ['Block IP: ' + ip, 'Enable rate limiting', 'Implement CAPTCHA', 'Enable 2FA', 'Review password policies']
          });
        }
      }

      if (event.eventType === 'Port Scan Detected' || (event.categories.includes('Port Activity') && event.categories.includes('Security Alerts'))) {
        portScans[ip] = portScans[ip] || [];
        portScans[ip].push(idx);
        if (portScans[ip].length >= 2) {
          threats.push({
            type: 'Port Scan Attack',
            severity: 'high',
            description: `Multiple port scans from ${ip}`,
            recommendation: 'This is reconnaissance activity. Investigate source IP and implement rate limiting. Enable IDS/IPS.',
            mitigation: ['Block IP: ' + ip, 'Enable IDS/IPS', 'Implement rate limiting', 'Review open ports', 'Monitor for follow-up attacks']
          });
        }
      }

      if (/icmp.*packet|ping.*flood|large.*packet/i.test(event.originalLog)) {
        threats.push({
          type: 'Possible DDoS Attack',
          severity: 'critical',
          description: 'Large ICMP packets detected - potential DDoS attack',
          recommendation: 'Enable rate limiting immediately. Contact ISP for upstream filtering if needed.',
          mitigation: ['Enable rate limiting', 'Activate anti-DDoS rules', 'Contact ISP', 'Monitor bandwidth', 'Consider DDoS protection service']
        });
      }

      if (event.threatLevel === 'critical' && /disk|memory|cpu/i.test(event.originalLog)) {
        threats.push({
          type: 'Resource Exhaustion',
          severity: 'critical',
          description: 'Critical resource usage - possible DoS or system failure',
          recommendation: 'Investigate top processes immediately. Check for malicious activity or resource attacks.',
          mitigation: ['Identify resource-consuming processes', 'Kill suspicious processes', 'Clear logs/temp files', 'Check for attacks', 'Scale infrastructure']
        });
      }

      if (event.categories.includes('Data Transfer') && /unusual|abnormal|large/i.test(event.originalLog)) {
        threats.push({
          type: 'Suspicious Data Transfer',
          severity: 'high',
          description: 'Unusual data transfer detected - possible exfiltration',
          recommendation: 'Review destination IPs. Check for unauthorized transfers. Analyze traffic patterns.',
          mitigation: ['Review destination IPs', 'Block suspicious destinations', 'Investigate source', 'Check for unauthorized access', 'Review DLP policies']
        });
      }
    });

    return threats.filter((threat, index, self) => index === self.findIndex((t) => t.type === threat.type && t.description === threat.description));
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

      // Rule 1: Automated polling — find repeated event types with suspiciously regular intervals
      const typeGroups = {};
      session.events.forEach(event => {
        const t = event.eventType;
        if (!typeGroups[t]) typeGroups[t] = [];
        typeGroups[t].push(event);
      });

      let bestAutomation = null;
      Object.entries(typeGroups).forEach(([type, evts]) => {
        if (evts.length < 4) return;
        const stats = computeIntervalStats(evts.map(e => e.parameters.timestamp).filter(Boolean));
        if (!stats) return;
        const cv = stats.stdDev / stats.mean;
        let score = cv < 0.03 ? 95 : cv < 0.10 ? 80 : cv < 0.20 ? 65 : cv < 0.35 ? 45 : 0;
        if (score === 0) return;
        if (evts.length >= 10) score = Math.min(score + 4, 99);
        if (!bestAutomation || score > bestAutomation.score) {
          const sortedTs = timestamps
            .map(ts => ({ ts, secs: parseTimestampToSeconds(ts) }))
            .filter(x => x.secs !== null)
            .sort((a, b) => a.secs - b.secs);
          const sparklineData = sortedTs.slice(1).map((x, i) => ({ idx: i + 1, interval: x.secs - sortedTs[i].secs }));
          bestAutomation = { type, count: evts.length, stats, score, sparklineData };
        }
      });

      if (bestAutomation) {
        sessionFindings.push({
          type: 'Automated API Polling',
          confidence: bestAutomation.score,
          icon: '🤖',
          detail: `"${bestAutomation.type}" called ${bestAutomation.count} times — mean interval ${bestAutomation.stats.mean.toFixed(1)}s (σ = ${bestAutomation.stats.stdDev.toFixed(2)}s)`,
          mitigations: ['Rate-limit or block this account/IP', 'Require re-authentication', 'Audit accessed data', 'Check for credential compromise'],
          sparklineData: bestAutomation.sparklineData
        });
      }

      // Rule 2: Reconnaissance — single session hitting many distinct endpoint types
      if (session.eventTypes.size >= 5 && session.events.length >= 8) {
        sessionFindings.push({
          type: 'Potential Reconnaissance',
          confidence: Math.min(45 + session.eventTypes.size * 4, 80),
          icon: '🔍',
          detail: `Accessed ${session.eventTypes.size} distinct endpoint types across ${session.events.length} requests`,
          mitigations: ['Review authorization per endpoint', 'Enable per-endpoint rate limiting', 'Flag account for manual review']
        });
      }

      // Rule 3: After-hours access (before 06:00 or after 22:00)
      const afterHours = session.events.filter(e => {
        const s = parseTimestampToSeconds(e.parameters.timestamp || '');
        if (s === null) return false;
        const h = Math.floor(s / 3600);
        return h < 6 || h >= 22;
      });
      if (afterHours.length >= 2) {
        sessionFindings.push({
          type: 'After-Hours Access',
          confidence: 65,
          icon: '🌙',
          detail: `${afterHours.length} events outside business hours (before 06:00 or after 22:00)`,
          mitigations: ['Verify after-hours access rights', 'Alert security team', 'Review for data exfiltration']
        });
      }

      // Rule 4: Brute force / account takeover — many failed logins, possibly followed by success
      const failedLogins = session.events.filter(e =>
        /fail|denied|401|403/i.test(e.originalLog) && /login|auth/i.test(e.originalLog)
      );
      if (failedLogins.length >= 3) {
        const hasSuccess = session.events.some((e, i) =>
          /success|logged in/i.test(e.originalLog) && /login|auth/i.test(e.originalLog) &&
          session.events.slice(0, i).some(p => /fail|denied|401|403/i.test(p.originalLog))
        );
        sessionFindings.push({
          type: hasSuccess ? 'Credential Stuffing / Account Takeover' : 'Brute Force Attempt',
          confidence: hasSuccess ? 90 : 75,
          icon: '🔑',
          detail: `${failedLogins.length} failed login attempt${failedLogins.length > 1 ? 's' : ''}${hasSuccess ? ' followed by successful authentication' : ''}`,
          mitigations: ['Lock account immediately', 'Force password reset', 'Block source IP', 'Enable MFA']
        });
      }

      // Rule 5: Session hijacking — same user active from multiple IPs with overlapping time windows
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
            sessionFindings.push({
              type: 'Possible Session Hijacking',
              confidence: 80,
              icon: '👥',
              detail: `User active simultaneously from ${overlapping.length} IPs: ${overlapping.join(', ')}`,
              mitigations: ['Invalidate all active sessions', 'Force re-authentication', 'Investigate both source IPs', 'Enable geo-velocity checks']
            });
          } else {
            sessionFindings.push({
              type: 'Multi-IP Access',
              confidence: 55,
              icon: '🔀',
              detail: `Same user accessed from ${distinctIPs.length} different IPs: ${distinctIPs.join(', ')}`,
              mitigations: ['Verify legitimate device switching', 'Check for shared credential use', 'Review access locations']
            });
          }
        }
      }

      // Rule 6: Endpoint enumeration — many distinct endpoint types hit in a short burst window
      if (session.events.length >= 5) {
        const sortedByTime = session.events
          .map(e => ({ type: e.eventType, ts: parseTimestampToSeconds(e.parameters.timestamp || '') }))
          .filter(e => e.ts !== null)
          .sort((a, b) => a.ts - b.ts);
        let enumerationFlagged = false;
        for (let i = 0; i < sortedByTime.length && !enumerationFlagged; i++) {
          const windowEnd = sortedByTime[i].ts + 120;
          const inWindow = sortedByTime.filter(e => e.ts >= sortedByTime[i].ts && e.ts <= windowEnd);
          const distinct = new Set(inWindow.map(e => e.type));
          if (distinct.size >= 4 && inWindow.length >= 6) {
            sessionFindings.push({
              type: 'Endpoint Enumeration',
              confidence: 70,
              icon: '📡',
              detail: `${distinct.size} distinct endpoint types accessed within a 2-minute window`,
              mitigations: ['Enable anomaly-based rate limiting', 'Review all accessed endpoints', 'Audit authorization logs']
            });
            enumerationFlagged = true;
          }
        }
      }

      if (sessionFindings.length > 0) {
        findings.push({
          identifier: session.identifier,
          identifierType: session.identifierType,
          totalEvents: session.events.length,
          uniqueEventTypes: session.eventTypes.size,
          behaviorSequence: buildBehaviorSequence(session.events),
          riskScore: Math.max(...sessionFindings.map(f => f.confidence)),
          findings: sessionFindings
        });
      }
    });

    return findings.sort((a, b) => b.riskScore - a.riskScore);
  };

  const analyzeFromPaste = () => {
    if (!logText.trim()) return;
    setLoading(true);
    setTimeout(() => { analyzeLogFile(logText.trim(), 'pasted_log.txt'); setLoading(false); }, 300);
  };

  const generateReport = () => {
    if (!analysis) return;
    const timestamp = new Date().toLocaleString();
    const filename = analysis.stats.fileName || 'Unknown';
    const threatRows = analysis.threats.map((t, i) => `
      <div class="card ${t.severity}">
        <div class="card-header">
          <span class="card-num">[${i + 1}]</span>
          <span class="card-title">${t.type}</span>
          <span class="badge ${t.severity}">${t.severity.toUpperCase()}</span>
        </div>
        <p class="desc">${t.description}</p>
        <p class="rec-label">Recommendation:</p>
        <p class="desc">${t.recommendation}</p>
        ${t.mitigation ? `<div class="chips">${t.mitigation.map(m => `<span class="chip">${m}</span>`).join('')}</div>` : ''}
      </div>`).join('');
    const investigationRows = (analysis.investigation || []).map((session, i) => `
      <div class="card ${session.riskScore >= 90 ? 'critical' : session.riskScore >= 70 ? 'high' : 'medium'}">
        <div class="card-header">
          <span class="card-num">[${i + 1}]</span>
          <span class="card-title">${session.identifierType === 'user' ? 'User' : 'IP'}: ${session.identifier}</span>
          <span class="risk-badge">${session.riskScore}/100 Risk</span>
        </div>
        <p class="meta">${session.totalEvents} events · ${session.uniqueEventTypes} endpoint types</p>
        <p class="seq-label">Behavior Sequence:</p>
        <div class="seq">${session.behaviorSequence.map(s => `${s.type}${s.count > 1 ? ` ×${s.count}` : ''}`).join(' → ')}</div>
        ${session.findings.map(f => `
          <div class="sub-card">
            <div class="sub-header">
              <span>${f.icon} ${f.type}</span>
              <span class="conf">${f.confidence}% confidence</span>
            </div>
            <p class="desc">${f.detail}</p>
            <div class="chips">${f.mitigations.map(m => `<span class="chip">${m}</span>`).join('')}</div>
          </div>`).join('')}
      </div>`).join('');
    const html = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>CyberNyx Report</title><style>
      *{margin:0;padding:0;box-sizing:border-box}
      body{font-family:'Segoe UI',Arial,sans-serif;color:#1a1a2e;background:#fff;padding:40px;max-width:960px;margin:0 auto}
      @media print{body{padding:20px}.no-print{display:none}@page{margin:20mm}}
      .report-header{border-bottom:3px solid #3b82f6;padding-bottom:20px;margin-bottom:32px}
      .logo{background:linear-gradient(135deg,#3b82f6,#06b6d4);color:white;padding:5px 14px;border-radius:8px;font-size:13px;font-weight:800;margin-right:12px}
      .report-title{font-size:26px;font-weight:800;color:#1e3a5f;display:flex;align-items:center;margin-bottom:8px}
      .report-meta{color:#64748b;font-size:13px}
      .section{margin-bottom:32px}
      .section-title{font-size:14px;font-weight:700;color:#1e3a5f;border-left:4px solid #3b82f6;padding-left:10px;margin-bottom:16px;text-transform:uppercase;letter-spacing:.06em}
      .stats-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px}
      .stat-box{border-radius:8px;padding:14px;text-align:center}
      .stat-box.critical{background:#fef2f2;border:1px solid #fca5a5}.stat-box.high{background:#fff7ed;border:1px solid #fed7aa}
      .stat-box.medium{background:#fefce8;border:1px solid #fde68a}.stat-box.low{background:#f0fdf4;border:1px solid #86efac}
      .stat-num{font-size:30px;font-weight:800}
      .stat-box.critical .stat-num{color:#dc2626}.stat-box.high .stat-num{color:#ea580c}
      .stat-box.medium .stat-num{color:#ca8a04}.stat-box.low .stat-num{color:#16a34a}
      .stat-label{font-size:11px;color:#64748b;font-weight:600;margin-top:4px;text-transform:uppercase}
      .summary-row{display:flex;gap:24px;flex-wrap:wrap;color:#334155;font-size:14px}
      .summary-row strong{color:#1e3a5f}
      .card{border-radius:8px;padding:16px;margin-bottom:12px;border-left:4px solid}
      .card.critical{background:#fef2f2;border-color:#dc2626}.card.high{background:#fff7ed;border-color:#ea580c}
      .card.medium{background:#fefce8;border-color:#ca8a04}.card.low{background:#f0fdf4;border-color:#16a34a}
      .card-header{display:flex;align-items:center;gap:10px;margin-bottom:8px;flex-wrap:wrap}
      .card-num{color:#64748b;font-size:12px;font-weight:700}
      .card-title{font-weight:700;font-size:15px;color:#1e3a5f;flex:1}
      .badge{padding:2px 10px;border-radius:99px;font-size:11px;font-weight:700}
      .badge.critical{background:#dc2626;color:white}.badge.high{background:#ea580c;color:white}
      .badge.medium{background:#ca8a04;color:white}.badge.low{background:#16a34a;color:white}
      .risk-badge{font-weight:800;color:#dc2626;font-size:14px}
      .desc{color:#475569;font-size:13px;margin-bottom:8px;line-height:1.5}
      .rec-label{font-size:11px;font-weight:700;color:#3b82f6;margin-bottom:3px;text-transform:uppercase}
      .meta{font-size:12px;color:#64748b;margin-bottom:8px}
      .seq-label{font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:.05em;margin-bottom:4px}
      .seq{font-family:monospace;font-size:12px;color:#1e3a5f;background:#f1f5f9;padding:8px 12px;border-radius:6px;margin-bottom:12px;word-break:break-word;line-height:1.6}
      .sub-card{background:white;border-radius:6px;padding:12px;margin-top:10px;border:1px solid #e2e8f0}
      .sub-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;flex-wrap:wrap;gap:6px}
      .sub-header span:first-child{font-weight:700;font-size:13px;color:#1e3a5f}
      .conf{font-size:11px;font-weight:700;padding:2px 8px;border-radius:99px;background:#dc2626;color:white}
      .chips{display:flex;flex-wrap:wrap;gap:5px;margin-top:8px}
      .chip{font-size:11px;padding:3px 10px;border-radius:99px;background:#dbeafe;color:#1d4ed8;font-weight:600}
      .footer{margin-top:40px;padding-top:16px;border-top:1px solid #e2e8f0;color:#94a3b8;font-size:11px;text-align:center}
      .print-btn{position:fixed;top:20px;right:20px;background:#3b82f6;color:white;border:none;padding:10px 20px;border-radius:8px;cursor:pointer;font-size:14px;font-weight:600;box-shadow:0 4px 12px rgba(59,130,246,.4)}
      .print-btn:hover{background:#2563eb}
      .clean-bill{background:#f0fdf4;border:2px solid #86efac;border-radius:8px;padding:20px;text-align:center;color:#16a34a}
    </style></head><body>
      <button class="print-btn no-print" onclick="window.print()">Save as PDF</button>
      <div class="report-header">
        <div class="report-title"><span class="logo">CyberNyx</span>Security Investigation Report</div>
        <div class="report-meta">Generated: ${timestamp} &nbsp;·&nbsp; Source: ${filename} &nbsp;·&nbsp; CyberNyx Log Analyzer</div>
      </div>
      <div class="section">
        <div class="section-title">Executive Summary</div>
        <div class="stats-grid">
          <div class="stat-box critical"><div class="stat-num">${analysis.stats.critical}</div><div class="stat-label">Critical</div></div>
          <div class="stat-box high"><div class="stat-num">${analysis.stats.high}</div><div class="stat-label">High Risk</div></div>
          <div class="stat-box medium"><div class="stat-num">${analysis.stats.medium}</div><div class="stat-label">Medium Risk</div></div>
          <div class="stat-box low"><div class="stat-num">${analysis.stats.low}</div><div class="stat-label">Low Risk</div></div>
        </div>
        <div class="summary-row">
          <span><strong>${analysis.stats.total}</strong> events analyzed</span>
          <span><strong>${analysis.stats.uniqueIPs}</strong> unique IPs</span>
          <span><strong>${analysis.threats.length}</strong> active threat${analysis.threats.length !== 1 ? 's' : ''}</span>
          <span><strong>${(analysis.investigation || []).length}</strong> suspicious session${(analysis.investigation || []).length !== 1 ? 's' : ''}</span>
        </div>
      </div>
      ${analysis.threats.length > 0 ? `<div class="section"><div class="section-title">Active Threats (${analysis.threats.length})</div>${threatRows}</div>` : ''}
      ${(analysis.investigation || []).length > 0 ? `<div class="section"><div class="section-title">Behavioral Investigation (${(analysis.investigation || []).length} Suspicious Sessions)</div>${investigationRows}</div>` : ''}
      ${analysis.threats.length === 0 && (analysis.investigation || []).length === 0 ? `<div class="section"><div class="clean-bill"><strong>No significant threats detected.</strong> Logs appear within normal parameters.</div></div>` : ''}
      <div class="footer">CyberNyx Log Analyzer · ${timestamp} · Auto-generated — review with a qualified security analyst.</div>
    </body></html>`;
    const w = window.open('', '_blank');
    if (w) { w.document.write(html); w.document.close(); }
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
      alert('Error reading file');
    } finally {
      setLoading(false);
    }
  };

  const loadSampleFile = (type) => {
    setLoading(true);
    setTimeout(() => { analyzeLogFile(sampleLogs[type], `${type}_sample.log`); setLoading(false); }, 500);
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
      timelineData[timeKey] = (timelineData[timeKey] || 0) + 1;
      
      results.push({ lineNumber: index + 1, originalLog: line, categories, eventType, parameters, threatLevel, isAlert: threatLevel === 'critical' || threatLevel === 'high' });
    });

    const ipIntel = {};
    Array.from(uniqueIPs).forEach(ip => { ipIntel[ip] = generateIPIntelligence(ip); });

    const threats = detectAdvancedThreats(results);
    const investigation = runInvestigationEngine(results);
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

    const timeline = Object.entries(timelineData).map(([time, count]) => ({ time, count })).sort((a, b) => a.time.localeCompare(b.time));
    setAnalysis({ results, stats, threats, investigation, timeline, ipIntelligence: ipIntel });
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

  const toggleBookmark = (lineNumber) => {
    const newBookmarks = new Set(bookmarkedEvents);
    newBookmarks.has(lineNumber) ? newBookmarks.delete(lineNumber) : newBookmarks.add(lineNumber);
    setBookmarkedEvents(newBookmarks);
  };

  const getTopIPs = () => {
    if (!analysis) return [];
    const ipCounts = {};
    analysis.results.forEach(r => { const ip = r.parameters.sourceIP; if (ip) ipCounts[ip] = (ipCounts[ip] || 0) + 1; });
    return Object.entries(ipCounts).sort(([,a], [,b]) => b - a).slice(0, 5).map(([ip, count]) => ({ ip, count }));
  };

  const filteredResults = analysis?.results.filter(result => {
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
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
              <div className={`${darkMode ? 'bg-white/10 border-white/20' : 'bg-white border-gray-200 shadow-lg'} rounded-lg p-6 border border-red-500/50`}>
                <div className="flex items-center justify-between mb-2">
                  <div>
                    <div className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Critical</div>
                    <div className="text-3xl font-bold text-red-400">{analysis.stats.critical}</div>
                  </div>
                  <AlertTriangle className="w-10 h-10 text-red-400 opacity-50" />
                </div>
              </div>
              
              <div className={`${darkMode ? 'bg-white/10 border-white/20' : 'bg-white border-gray-200 shadow-lg'} rounded-lg p-6 border border-orange-500/50`}>
                <div className="flex items-center justify-between mb-2">
                  <div>
                    <div className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>High Risk</div>
                    <div className="text-3xl font-bold text-orange-400">{analysis.stats.high}</div>
                  </div>
                  <AlertTriangle className="w-10 h-10 text-orange-400 opacity-50" />
                </div>
              </div>
              
              <div className={`${darkMode ? 'bg-white/10 border-white/20' : 'bg-white border-gray-200 shadow-lg'} rounded-lg p-6 border border-yellow-500/50`}>
                <div className="flex items-center justify-between mb-2">
                  <div>
                    <div className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Medium Risk</div>
                    <div className="text-3xl font-bold text-yellow-400">{analysis.stats.medium}</div>
                  </div>
                  <Activity className="w-10 h-10 text-yellow-400 opacity-50" />
                </div>
              </div>
              
              <div className={`${darkMode ? 'bg-white/10 border-white/20' : 'bg-white border-gray-200 shadow-lg'} rounded-lg p-6 border border-green-500/50`}>
                <div className="flex items-center justify-between mb-2">
                  <div>
                    <div className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Low Risk</div>
                    <div className="text-3xl font-bold text-green-400">{analysis.stats.low}</div>
                  </div>
                  <Shield className="w-10 h-10 text-green-400 opacity-50" />
                </div>
              </div>
            </div>

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
            {analysis.investigation && analysis.investigation.length > 0 && (
              <div className={`${darkMode ? 'bg-purple-900/20 border-purple-500/50' : 'bg-purple-50 border-purple-200'} rounded-lg p-6 mb-6 border-2`}>
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-2">
                    <Search className="w-6 h-6 text-purple-400" />
                    <h2 className={`text-2xl font-bold ${darkMode ? 'text-purple-400' : 'text-purple-700'}`}>
                      Behavioral Investigation ({analysis.investigation.length} suspicious session{analysis.investigation.length !== 1 ? 's' : ''})
                    </h2>
                  </div>
                  <button onClick={() => setShowInvestigation(!showInvestigation)} className={`p-2 rounded ${darkMode ? 'bg-white/10 hover:bg-white/20' : 'bg-purple-100 hover:bg-purple-200'} transition-all`}>
                    {showInvestigation ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
                  </button>
                </div>

                {showInvestigation && (
                  <div className="space-y-4">
                    {analysis.investigation.map((session, idx) => {
                      const isCollapsed = collapsedSessions.has(idx);
                      const toggleSession = () => {
                        const next = new Set(collapsedSessions);
                        next.has(idx) ? next.delete(idx) : next.add(idx);
                        setCollapsedSessions(next);
                      };
                      return (
                        <div key={idx} className={`${darkMode ? 'bg-slate-900/70' : 'bg-white'} rounded-lg border-l-4 overflow-hidden ${
                          session.riskScore >= 90 ? 'border-red-500' : session.riskScore >= 70 ? 'border-orange-500' : 'border-yellow-500'
                        }`}>
                          {/* Session card header — always visible, click to collapse */}
                          <button onClick={toggleSession} className="w-full p-5 text-left">
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-3 flex-wrap">
                                <span className={`text-xs font-semibold px-2 py-1 rounded ${darkMode ? 'bg-blue-500/20 text-blue-300' : 'bg-blue-100 text-blue-700'}`}>
                                  {session.identifierType === 'user' ? '👤 User' : '🌐 IP'}
                                </span>
                                <span className={`font-mono font-bold text-lg ${darkMode ? 'text-white' : 'text-gray-900'}`}>{session.identifier}</span>
                                <span className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                                  {session.totalEvents} events · {session.findings.length} finding{session.findings.length !== 1 ? 's' : ''}
                                </span>
                              </div>
                              <div className="flex items-center gap-3 flex-shrink-0">
                                <div className="text-right">
                                  <div className={`text-2xl font-bold ${session.riskScore >= 90 ? 'text-red-400' : session.riskScore >= 70 ? 'text-orange-400' : 'text-yellow-400'}`}>
                                    {session.riskScore}<span className={`text-xs font-normal ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>/100</span>
                                  </div>
                                </div>
                                {isCollapsed ? <ChevronDown className="w-4 h-4 text-gray-400" /> : <ChevronUp className="w-4 h-4 text-gray-400" />}
                              </div>
                            </div>
                          </button>

                          {/* Collapsible body */}
                          {!isCollapsed && (
                            <div className="px-5 pb-5">
                              {/* Behavior Sequence */}
                              {session.behaviorSequence.length > 0 && (
                                <div className="mb-4">
                                  <div className={`text-xs font-semibold tracking-widest ${darkMode ? 'text-gray-500' : 'text-gray-400'} mb-2`}>BEHAVIOR SEQUENCE</div>
                                  <div className="flex items-center gap-2 flex-wrap">
                                    {session.behaviorSequence.map((step, i) => (
                                      <React.Fragment key={i}>
                                        {i > 0 && <span className={`${darkMode ? 'text-gray-500' : 'text-gray-400'} text-sm`}>→</span>}
                                        <span className={`px-2 py-1 rounded text-xs font-medium ${
                                          step.count > 3
                                            ? darkMode ? 'bg-red-900/40 text-red-300 border border-red-500/50' : 'bg-red-100 text-red-700 border border-red-300'
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
                                    finding.confidence >= 90
                                      ? darkMode ? 'bg-red-900/25 border border-red-500/40' : 'bg-red-50 border border-red-200'
                                      : finding.confidence >= 70
                                        ? darkMode ? 'bg-orange-900/25 border border-orange-500/40' : 'bg-orange-50 border border-orange-200'
                                        : darkMode ? 'bg-yellow-900/25 border border-yellow-500/40' : 'bg-yellow-50 border border-yellow-200'
                                  }`}>
                                    <div className="flex items-center justify-between mb-2 flex-wrap gap-2">
                                      <div className="flex items-center gap-2">
                                        <span className="text-xl">{finding.icon}</span>
                                        <span className={`font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>{finding.type}</span>
                                      </div>
                                      <span className={`text-xs font-bold px-2 py-1 rounded ${
                                        finding.confidence >= 90 ? 'bg-red-500 text-white' :
                                        finding.confidence >= 70 ? 'bg-orange-500 text-white' : 'bg-yellow-500 text-black'
                                      }`}>{finding.confidence}% confidence</span>
                                    </div>
                                    <p className={`text-sm mb-3 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>{finding.detail}</p>

                                    {/* Interval sparkline for automation findings */}
                                    {finding.sparklineData && finding.sparklineData.length > 1 && (
                                      <div className="mb-3">
                                        <div className={`text-xs font-semibold tracking-widest ${darkMode ? 'text-gray-500' : 'text-gray-400'} mb-1`}>REQUEST INTERVAL PATTERN</div>
                                        <div className={`rounded p-2 ${darkMode ? 'bg-black/30' : 'bg-white'}`}>
                                          <ResponsiveContainer width="100%" height={60}>
                                            <LineChart data={finding.sparklineData} margin={{ top: 4, right: 4, bottom: 4, left: 4 }}>
                                              <Line type="monotone" dataKey="interval" stroke={finding.confidence >= 90 ? '#ef4444' : '#f97316'} strokeWidth={2} dot={{ r: 3, fill: finding.confidence >= 90 ? '#ef4444' : '#f97316' }} />
                                              <Tooltip
                                                contentStyle={{ backgroundColor: darkMode ? '#1e293b' : '#fff', border: '1px solid #3b82f6', borderRadius: '6px', fontSize: '11px' }}
                                                formatter={(v) => [`${v}s`, 'Interval']}
                                                labelFormatter={(l) => `Request #${l}`}
                                              />
                                            </LineChart>
                                          </ResponsiveContainer>
                                          <div className={`text-center text-xs mt-1 ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>
                                            Flat = automation · Spiky = human
                                          </div>
                                        </div>
                                      </div>
                                    )}

                                    <div className="flex flex-wrap gap-2">
                                      {finding.mitigations.map((m, mi) => (
                                        <span key={mi} className={`text-xs px-2 py-1 rounded ${darkMode ? 'bg-blue-900/30 text-blue-300 border border-blue-500/30' : 'bg-blue-50 text-blue-700 border border-blue-200'}`}>{m}</span>
                                      ))}
                                    </div>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}

            {/* Charts & Top IPs Section */}
            {showCharts && (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
                {/* Severity Distribution Pie Chart */}
                <div className={`${darkMode ? 'bg-white/10 border-white/20' : 'bg-white border-gray-200 shadow-lg'} rounded-lg p-6 border`}>
                  <h3 className={`text-lg font-semibold mb-4 flex items-center gap-2 ${darkMode ? '' : 'text-gray-900'}`}>
                    <Activity className="w-5 h-5 text-blue-400" />
                    Severity Distribution
                  </h3>
                  <ResponsiveContainer width="100%" height={250}>
                    <PieChart>
                      <Pie
                        data={[
                          { name: 'Critical', value: analysis.stats.critical, color: '#ef4444' },
                          { name: 'High', value: analysis.stats.high, color: '#f97316' },
                          { name: 'Medium', value: analysis.stats.medium, color: '#eab308' },
                          { name: 'Low', value: analysis.stats.low, color: '#22c55e' }
                        ].filter(item => item.value > 0)}
                        cx="50%"
                        cy="50%"
                        outerRadius={80}
                        dataKey="value"
                        label={({ name, value, percent }) => `${name}: ${value} (${(percent * 100).toFixed(0)}%)`}
                      >
                        {[
                          { name: 'Critical', value: analysis.stats.critical, color: '#ef4444' },
                          { name: 'High', value: analysis.stats.high, color: '#f97316' },
                          { name: 'Medium', value: analysis.stats.medium, color: '#eab308' },
                          { name: 'Low', value: analysis.stats.low, color: '#22c55e' }
                        ].filter(item => item.value > 0).map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip 
                        contentStyle={{ 
                          backgroundColor: darkMode ? '#1e293b' : '#ffffff', 
                          border: '2px solid #3b82f6',
                          borderRadius: '8px',
                          color: darkMode ? '#e5e7eb' : '#000000'
                        }}
                        itemStyle={{ color: darkMode ? '#e5e7eb' : '#000000', fontWeight: 'bold' }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </div>

                {/* Top Source IPs */}
                <div className={`${darkMode ? 'bg-white/10 border-white/20' : 'bg-white border-gray-200 shadow-lg'} rounded-lg p-6 border`}>
                  <h3 className={`text-lg font-semibold mb-4 flex items-center gap-2 ${darkMode ? '' : 'text-gray-900'}`}>
                    <MapPin className="w-5 h-5 text-red-400" />
                    Top Source IPs
                  </h3>
                  <div className="space-y-2">
                    {getTopIPs().map((item, i) => (
                      <div key={i} className={`flex justify-between items-center ${darkMode ? 'bg-white/5' : 'bg-gray-50'} rounded p-3`}>
                        <div>
                          <div className={`font-semibold text-sm ${darkMode ? 'text-white' : 'text-gray-900'}`}>{item.ip}</div>
                          {analysis.ipIntelligence[item.ip] && (
                            <div className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                              {analysis.ipIntelligence[item.ip].country} • {analysis.ipIntelligence[item.ip].city}
                            </div>
                          )}
                        </div>
                        <div className="text-right">
                          <div className="text-lg font-bold text-blue-400">{item.count}</div>
                          {analysis.ipIntelligence[item.ip] && (
                            <div className={`text-xs font-semibold ${
                              analysis.ipIntelligence[item.ip].risk === 'High' ? 'text-red-400' : 
                              analysis.ipIntelligence[item.ip].risk === 'Medium' ? 'text-yellow-400' : 
                              'text-green-400'
                            }`}>
                              {analysis.ipIntelligence[item.ip].risk} Risk
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
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

            {/* Filters and Search */}
            <div className={`${darkMode ? 'bg-white/10 border-white/20' : 'bg-white border-gray-200 shadow-lg'} rounded-lg p-4 mb-6 border`}>
              <div className="flex flex-col md:flex-row gap-4 items-start md:items-center justify-between">
                <div className="flex flex-col md:flex-row items-start md:items-center gap-4 flex-1 flex-wrap">
                  <div className="flex items-center gap-2">
                    <Filter className="w-5 h-5 text-blue-400" />
                    <select value={filterCategory} onChange={(e) => setFilterCategory(e.target.value)} className={`${darkMode ? 'bg-white/5 border-white/20 text-white' : 'bg-gray-50 border-gray-300 text-gray-900'} border rounded px-3 py-2 text-sm`}>
                      <option value="all">All Events ({analysis.results.length})</option>
                      <option value="alerts">⚠️ Alerts Only ({analysis.stats.alerts})</option>
                      <option value="bookmarked">🔖 Bookmarked ({bookmarkedEvents.size})</option>
                      <option disabled>────────────────</option>
                      <option disabled>📊 Filter by Category:</option>
                      {Object.entries(analysis.stats.categoryBreakdown).sort(([,a], [,b]) => b - a).map(([cat, count]) => (
                        <option key={cat} value={cat}>{eventCategories[cat]?.icon} {cat} ({count} matches)</option>
                      ))}
                    </select>
                  </div>

                  <div className="flex items-center gap-2">
                    <select value={filterSeverity} onChange={(e) => setFilterSeverity(e.target.value)} className={`${darkMode ? 'bg-white/5 border-white/20 text-white' : 'bg-gray-50 border-gray-300 text-gray-900'} border rounded px-3 py-2 text-sm`}>
                      <option value="all">All Severity Levels</option>
                      <option value="critical">🔴 Critical ({analysis.stats.critical})</option>
                      <option value="high">🟠 High ({analysis.stats.high})</option>
                      <option value="medium">🟡 Medium ({analysis.stats.medium})</option>
                      <option value="low">🟢 Low ({analysis.stats.low})</option>
                    </select>
                  </div>
                  
                  <div className="flex items-center gap-2 flex-1 max-w-md">
                    <Search className="w-5 h-5 text-blue-400" />
                    <input type="text" placeholder="Search logs..." value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} className={`${darkMode ? 'bg-white/5 border-white/20 text-white placeholder-gray-400' : 'bg-gray-50 border-gray-300 text-gray-900 placeholder-gray-500'} border rounded px-3 py-2 text-sm flex-1`} />
                  </div>

                  {getActiveFilterName() && (
                    <div className="flex items-center gap-2">
                      <span className="px-3 py-1 bg-blue-500 text-white rounded-full text-sm font-medium">{getActiveFilterName()}</span>
                      <button onClick={clearFilters} className="px-3 py-1 bg-red-500/20 hover:bg-red-500/30 border border-red-500/50 text-red-400 rounded-full text-sm font-medium transition-all">Clear</button>
                    </div>
                  )}
                </div>
                
                <div className="flex gap-2">
                  <button onClick={() => setShowCharts(!showCharts)} className="flex items-center gap-2 bg-purple-500/20 hover:bg-purple-500/30 border border-purple-500/50 rounded px-3 py-2 text-sm transition-all">
                    {showCharts ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    Charts
                  </button>
                  <button onClick={() => exportResults('csv')} className="flex items-center gap-2 bg-green-500/20 hover:bg-green-500/30 border border-green-500/50 rounded px-3 py-2 text-sm transition-all">
                    <Download className="w-4 h-4" />
                    CSV
                  </button>
                  <button onClick={() => exportResults('json')} className="flex items-center gap-2 bg-blue-500/20 hover:bg-blue-500/30 border border-blue-500/50 rounded px-3 py-2 text-sm transition-all">
                    <Download className="w-4 h-4" />
                    JSON
                  </button>
                  <button onClick={generateReport} className="flex items-center gap-2 bg-red-500/20 hover:bg-red-500/30 border border-red-500/50 text-red-400 rounded px-3 py-2 text-sm font-semibold transition-all">
                    <FileText className="w-4 h-4" />
                    PDF Report
                  </button>
                </div>
              </div>
              
              <div className={`mt-2 text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                Showing {filteredResults.length} of {analysis.results.length} events
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