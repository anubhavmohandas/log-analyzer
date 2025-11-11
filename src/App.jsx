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
  const [darkMode, setDarkMode] = useState(true);
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
    
    const userPattern = /(?:user|username|account)[=:\s"']+([^"'\s]+)/i;
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
    setAnalysis({ results, stats, threats, timeline, ipIntelligence: ipIntel });
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
    <div className={`min-h-screen ${darkMode ? 'bg-slate-950 text-white' : 'bg-gradient-to-br from-gray-50 via-blue-50 to-gray-50 text-gray-900'} p-6 relative overflow-hidden`}>
      {/* Animated Background - Dark Mode Only */}
      {darkMode && (
        <>
          <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top_right,_var(--tw-gradient-stops))] from-blue-900/20 via-slate-950 to-slate-950"></div>
          <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_bottom_left,_var(--tw-gradient-stops))] from-purple-900/20 via-transparent to-transparent"></div>
          <div className="absolute top-0 -left-4 w-72 h-72 bg-purple-500 rounded-full mix-blend-multiply filter blur-3xl opacity-10 animate-pulse"></div>
          <div className="absolute top-0 -right-4 w-72 h-72 bg-blue-500 rounded-full mix-blend-multiply filter blur-3xl opacity-10 animate-pulse" style={{animationDelay: '2s'}}></div>
          <div className="absolute -bottom-8 left-20 w-72 h-72 bg-cyan-500 rounded-full mix-blend-multiply filter blur-3xl opacity-10 animate-pulse" style={{animationDelay: '4s'}}></div>
        </>
      )}
      
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
          <div className="flex items-center gap-2 mb-4">
            <Upload className="w-5 h-5 text-blue-400" />
            <h2 className={`text-xl font-semibold ${darkMode ? '' : 'text-gray-900'}`}>Upload Log File</h2>
          </div>
          
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
          
          {loading && (
            <div className={`mt-4 text-center ${darkMode ? 'text-blue-400' : 'text-blue-600'}`}>
              <Activity className="w-6 h-6 animate-spin inline-block mr-2" />
              Analyzing log file with advanced threat intelligence...
            </div>
          )}
          
          <div className="mt-6">
            <div className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'} mb-3`}>Or try a sample log file:</div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
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