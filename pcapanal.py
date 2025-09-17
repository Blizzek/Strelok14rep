#!/usr/bin/env python3
"""
xsukax PCAP Network Traffic Analyzer
Advanced Network Analysis Tool for System Administrators
"""

import argparse
import json
import time
import sys
import re
from pathlib import Path
from datetime import datetime
from collections import defaultdict, Counter
from typing import Dict, List, Any
import statistics

# Scapy imports
try:
    from scapy.all import *
    SCAPY_AVAILABLE = True
except ImportError as e:
    print(f"Error: Scapy is required. Install with: pip install scapy")
    print(f"Details: {e}")
    sys.exit(1)

class PCAPAnalyzer:
    """Minimal yet comprehensive PCAP analyzer"""
    
    # Service ports
    PORTS = {
        20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
        53: 'DNS', 67: 'DHCP', 68: 'DHCP', 80: 'HTTP', 110: 'POP3',
        143: 'IMAP', 161: 'SNMP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS',
        587: 'SMTP', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 3306: 'MySQL',
        3389: 'RDP', 5432: 'PostgreSQL', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
    }
    
    # DNS types
    DNS_TYPES = {
        1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX',
        16: 'TXT', 28: 'AAAA', 33: 'SRV', 255: 'ANY'
    }
    
    # DNS response codes
    DNS_CODES = {
        0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN',
        4: 'NOTIMP', 5: 'REFUSED'
    }
    
    # Suspicious patterns
    SUSPICIOUS = [
        r'\.tk$', r'\.ml$', r'\.ga$', r'\.cf$',
        r'^[a-z0-9]{32,}', r'[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}',
        r'\.bit$', r'\.onion$'
    ]
    
    def __init__(self, level='standard'):
        self.level = level
        self.reset_stats()
    
    def reset_stats(self):
        """Initialize all statistics"""
        # Basic stats
        self.packets = 0
        self.bytes = 0
        self.start_time = None
        self.end_time = None
        self.malformed = 0
        
        # Protocol counts
        self.protocols = defaultdict(int)
        
        # IP statistics
        self.ip_conversations = defaultdict(lambda: {'packets': 0, 'bytes': 0, 'protocols': set()})
        self.ip_stats = defaultdict(lambda: {'sent': 0, 'received': 0, 'bytes_sent': 0, 'bytes_received': 0})
        
        # Port statistics
        self.port_stats = defaultdict(lambda: {'tcp': 0, 'udp': 0})
        self.tcp_flags = Counter()
        
        # DNS statistics
        self.dns_queries = Counter()
        self.dns_responses = Counter()
        self.dns_types = Counter()
        self.dns_codes = Counter()
        self.dns_servers = set()
        self.suspicious_domains = []
        self.nxdomain = []
        
        # Services and HTTP
        self.services = defaultdict(set)
        self.http_methods = Counter()
        self.http_status = Counter()
        self.http_hosts = Counter()
        
        # Security
        self.threats = []
        self.port_scans = []
        
        # Packet sizes
        self.packet_sizes = []
    
    def analyze(self, pcap_file: str) -> Dict:
        """Main analysis function"""
        print(f"\n{'='*60}")
        print(f"  PCAP Analysis: {pcap_file}")
        print(f"  Level: {self.level.upper()}")
        print(f"{'='*60}\n")
        
        if not Path(pcap_file).exists():
            raise FileNotFoundError(f"File not found: {pcap_file}")
        
        start = time.time()
        
        # Load packets
        print("Loading packets...")
        packets = rdpcap(pcap_file)
        
        if not packets:
            return {}
        
        print(f"Loaded {len(packets):,} packets")
        
        # Set time bounds
        self.start_time = float(packets[0].time)
        self.end_time = float(packets[-1].time)
        
        # Analyze packets
        total = len(packets)
        for i, pkt in enumerate(packets, 1):
            self._analyze_packet(pkt)
            if i % 5000 == 0:
                print(f"  Processed {i:,}/{total:,} packets...")
        
        # Post-processing
        self._detect_threats()
        
        # Generate report
        duration = time.time() - start
        report = self._generate_report(pcap_file, duration)
        
        print(f"\nAnalysis completed in {duration:.2f}s")
        self._print_summary(report)
        
        return report
    
    def _analyze_packet(self, pkt):
        """Analyze single packet"""
        try:
            self.packets += 1
            self.bytes += len(pkt)
            self.packet_sizes.append(len(pkt))
            
            # Layer 2 - Ethernet
            if pkt.haslayer(Ether):
                self.protocols['ethernet'] += 1
            
            # Layer 3 - Network
            if pkt.haslayer(IP):
                self.protocols['ipv4'] += 1
                self._analyze_ip(pkt[IP])
            elif pkt.haslayer(ARP):
                self.protocols['arp'] += 1
            
            # Check IPv6
            try:
                if pkt.haslayer('IPv6'):
                    self.protocols['ipv6'] += 1
            except:
                pass
            
            # Layer 4 - Transport
            if pkt.haslayer(TCP):
                self.protocols['tcp'] += 1
                self._analyze_tcp(pkt[TCP], pkt)
            elif pkt.haslayer(UDP):
                self.protocols['udp'] += 1
                self._analyze_udp(pkt[UDP], pkt)
            elif pkt.haslayer(ICMP):
                self.protocols['icmp'] += 1
            
            # Application Layer
            if pkt.haslayer(DNS):
                self.protocols['dns'] += 1
                self._analyze_dns(pkt[DNS], pkt)
            
            # HTTP/HTTPS detection
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                if tcp.dport in [80, 8080] or tcp.sport in [80, 8080]:
                    self.protocols['http'] += 1
                    self._analyze_http(pkt)
                elif tcp.dport == 443 or tcp.sport == 443:
                    self.protocols['https'] += 1
                    
        except Exception:
            self.malformed += 1
    
    def _analyze_ip(self, ip):
        """Analyze IP layer"""
        src, dst = ip.src, ip.dst
        
        # Conversation tracking
        key = f"{min(src, dst)} <-> {max(src, dst)}"
        self.ip_conversations[key]['packets'] += 1
        self.ip_conversations[key]['bytes'] += len(ip)
        
        # Protocol name
        proto_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        proto = proto_map.get(ip.proto, f'Proto-{ip.proto}')
        self.ip_conversations[key]['protocols'].add(proto)
        
        # IP statistics
        self.ip_stats[src]['sent'] += 1
        self.ip_stats[src]['bytes_sent'] += len(ip)
        self.ip_stats[dst]['received'] += 1
        self.ip_stats[dst]['bytes_received'] += len(ip)
    
    def _analyze_tcp(self, tcp, pkt):
        """Analyze TCP layer"""
        # Port statistics
        self.port_stats[tcp.sport]['tcp'] += 1
        self.port_stats[tcp.dport]['tcp'] += 1
        
        # Service detection
        for port in [tcp.sport, tcp.dport]:
            if port in self.PORTS and pkt.haslayer(IP):
                self.services[self.PORTS[port]].add(pkt[IP].src)
        
        # TCP flags
        if tcp.flags & 0x02: self.tcp_flags['SYN'] += 1
        if tcp.flags & 0x10: self.tcp_flags['ACK'] += 1
        if tcp.flags & 0x01: self.tcp_flags['FIN'] += 1
        if tcp.flags & 0x04: self.tcp_flags['RST'] += 1
        if tcp.flags & 0x08: self.tcp_flags['PSH'] += 1
        if tcp.flags & 0x20: self.tcp_flags['URG'] += 1
    
    def _analyze_udp(self, udp, pkt):
        """Analyze UDP layer"""
        # Port statistics
        self.port_stats[udp.sport]['udp'] += 1
        self.port_stats[udp.dport]['udp'] += 1
        
        # Service detection
        for port in [udp.sport, udp.dport]:
            if port in self.PORTS and pkt.haslayer(IP):
                self.services[self.PORTS[port]].add(pkt[IP].src)
    
    def _analyze_dns(self, dns, pkt):
        """Analyze DNS layer"""
        # Track DNS servers
        if pkt.haslayer(IP):
            if pkt[IP].sport == 53:
                self.dns_servers.add(pkt[IP].src)
            elif pkt[IP].dport == 53:
                self.dns_servers.add(pkt[IP].dst)
        
        # Query analysis
        if dns.qr == 0 and dns.qd:  # Query
            for q in dns.qd:
                if hasattr(q, 'qname'):
                    try:
                        domain = q.qname.decode('utf-8', errors='ignore').rstrip('.')
                        self.dns_queries[domain] += 1
                        
                        # Check suspicious
                        for pattern in self.SUSPICIOUS:
                            if re.search(pattern, domain, re.IGNORECASE):
                                if domain not in self.suspicious_domains:
                                    self.suspicious_domains.append(domain)
                                break
                        
                        # Check for potential tunneling
                        if len(domain) > 50 or domain.count('.') > 4:
                            if domain not in self.suspicious_domains:
                                self.suspicious_domains.append(domain)
                        
                        # Query type
                        qtype = self.DNS_TYPES.get(q.qtype, f'Type-{q.qtype}')
                        self.dns_types[qtype] += 1
                    except:
                        pass
        
        # Response analysis
        elif dns.qr == 1:  # Response
            # Response code
            rcode = self.DNS_CODES.get(dns.rcode, f'Code-{dns.rcode}')
            self.dns_codes[rcode] += 1
            
            # NXDOMAIN tracking
            if dns.rcode == 3 and dns.qd:
                for q in dns.qd:
                    if hasattr(q, 'qname'):
                        try:
                            domain = q.qname.decode('utf-8', errors='ignore').rstrip('.')
                            if domain not in self.nxdomain:
                                self.nxdomain.append(domain)
                        except:
                            pass
            
            # Response IPs
            if dns.an:
                for a in dns.an:
                    if hasattr(a, 'rdata'):
                        try:
                            self.dns_responses[str(a.rdata)] += 1
                        except:
                            pass
    
    def _analyze_http(self, pkt):
        """Analyze HTTP traffic"""
        if pkt.haslayer(Raw):
            try:
                data = pkt[Raw].load.decode('utf-8', errors='ignore')
                lines = data.split('\r\n')
                
                if lines and lines[0]:
                    # HTTP Request
                    methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']
                    for method in methods:
                        if lines[0].startswith(method):
                            self.http_methods[method] += 1
                            
                            # Extract Host
                            for line in lines[1:]:
                                if line.startswith('Host:'):
                                    host = line.split(':', 1)[1].strip()
                                    self.http_hosts[host] += 1
                                    break
                            break
                    
                    # HTTP Response
                    if lines[0].startswith('HTTP/'):
                        parts = lines[0].split()
                        if len(parts) > 1 and parts[1].isdigit():
                            self.http_status[int(parts[1])] += 1
            except:
                pass
    
    def _detect_threats(self):
        """Detect security threats"""
        # Port scan detection
        port_access = defaultdict(set)
        for port, stats in self.port_stats.items():
            if stats['tcp'] > 0 or stats['udp'] > 0:
                for ip in self.ip_stats.keys():
                    port_access[ip].add(port)
        
        for ip, ports in port_access.items():
            if len(ports) > 20:
                self.port_scans.append({'ip': ip, 'ports': len(ports)})
                self.threats.append({
                    'type': 'Port Scan',
                    'details': f'{ip} accessed {len(ports)} ports'
                })
        
        # DNS threats
        for domain in self.suspicious_domains[:5]:
            self.threats.append({
                'type': 'Suspicious DNS',
                'details': f'Domain: {domain}'
            })
        
        # DNS tunneling
        long_queries = [d for d in self.dns_queries.keys() if len(d) > 50]
        if long_queries:
            self.threats.append({
                'type': 'DNS Tunneling',
                'details': f'{len(long_queries)} abnormally long queries'
            })
        
        # Malformed packets
        if self.malformed > 0:
            self.threats.append({
                'type': 'Malformed Packets',
                'details': f'{self.malformed} malformed packets detected'
            })
    
    def _generate_report(self, file_path: str, duration: float) -> Dict:
        """Generate comprehensive report"""
        cap_duration = self.end_time - self.start_time if self.start_time else 0
        total = self.packets or 1
        
        return {
            'metadata': {
                'file': file_path,
                'timestamp': datetime.now().isoformat(),
                'analysis_duration': round(duration, 2),
                'capture_duration': round(cap_duration, 2),
                'level': self.level
            },
            
            'summary': {
                'packets': self.packets,
                'bytes': self.bytes,
                'bandwidth_mbps': round((self.bytes * 8) / (cap_duration * 1000000), 2) if cap_duration else 0,
                'unique_ips': len(self.ip_stats),
                'conversations': len(self.ip_conversations),
                'threats': len(self.threats),
                'services': len(self.services)
            },
            
            'protocols': {
                name: {
                    'count': count,
                    'percent': round(count / total * 100, 2)
                }
                for name, count in self.protocols.items()
            },
            
            'dns_analysis': {
                'summary': {
                    'queries': sum(self.dns_queries.values()),
                    'unique_domains': len(self.dns_queries),
                    'servers': list(self.dns_servers),
                    'suspicious': len(self.suspicious_domains),
                    'nxdomain': len(self.nxdomain)
                },
                'top_queries': dict(self.dns_queries.most_common(200)),
                'query_types': dict(self.dns_types),
                'response_codes': dict(self.dns_codes),
                'suspicious_domains': self.suspicious_domains[:10],
                'nxdomain_queries': self.nxdomain[:10]
            },
            
            'top_talkers': {
                'by_packets': sorted(
                    [(ip, s['sent'] + s['received']) for ip, s in self.ip_stats.items()],
                    key=lambda x: x[1], reverse=True
                )[:10],
                'by_bytes': sorted(
                    [(ip, s['bytes_sent'] + s['bytes_received']) for ip, s in self.ip_stats.items()],
                    key=lambda x: x[1], reverse=True
                )[:10]
            },
            
            'conversations': {
                'top': sorted(
                    [(c, d['packets'], d['bytes'], list(d['protocols'])) 
                     for c, d in self.ip_conversations.items()],
                    key=lambda x: x[1], reverse=True
                )[:100]
            },
            
            'services': {
                'detected': {s: list(h)[:5] for s, h in self.services.items()},
                'ports': sorted(
                    [(p, d['tcp'] + d['udp'], self.PORTS.get(p, 'Unknown'))
                     for p, d in self.port_stats.items() if d['tcp'] + d['udp'] > 0],
                    key=lambda x: x[1], reverse=True
                )[:20]
            },
            
            'http': {
                'methods': dict(self.http_methods),
                'status_codes': dict(self.http_status),
                'top_hosts': dict(self.http_hosts.most_common(10))
            } if self.http_methods else {},
            
            'security': {
                'threats': self.threats,
                'port_scans': self.port_scans,
                'malformed': self.malformed
            },
            
            'tcp_flags': dict(self.tcp_flags),
            
            'packet_stats': {
                'sizes': {
                    'min': min(self.packet_sizes) if self.packet_sizes else 0,
                    'max': max(self.packet_sizes) if self.packet_sizes else 0,
                    'avg': round(statistics.mean(self.packet_sizes), 2) if self.packet_sizes else 0,
                    'median': round(statistics.median(self.packet_sizes), 2) if self.packet_sizes else 0
                }
            }
        }
    
    def _print_summary(self, report):
        """Print analysis summary"""
        print(f"\n{'='*60}")
        print("  ANALYSIS SUMMARY")
        print(f"{'='*60}")
        
        s = report['summary']
        print(f"\nStatistics:")
        print(f"  Packets: {s['packets']:,}")
        print(f"  Bytes: {s['bytes']:,}")
        print(f"  Bandwidth: {s['bandwidth_mbps']} Mbps")
        print(f"  IPs: {s['unique_ips']}")
        print(f"  Conversations: {s['conversations']}")
        
        d = report['dns_analysis']['summary']
        print(f"\nDNS:")
        print(f"  Queries: {d['queries']}")
        print(f"  Domains: {d['unique_domains']}")
        print(f"  Suspicious: {d['suspicious']}")
        print(f"  NXDOMAIN: {d['nxdomain']}")
        
        if report['security']['threats']:
            print(f"\nSecurity:")
            for t in report['security']['threats'][:3]:
                print(f"  {t['type']}: {t['details']}")
        
        print(f"{'='*60}")
    
    def export_json(self, report: Dict, output_file: str):
        """Export report as JSON"""
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str, ensure_ascii=False)
        print(f"JSON: {output_file}")
    
    def export_html(self, report: Dict, output_file: str):
        """Export report as HTML"""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>xsukax PCAP Analysis Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {{margin:0;padding:0;box-sizing:border-box}}
        body {{font-family:Arial,sans-serif;background:linear-gradient(135deg,#667eea,#764ba2);padding:20px}}
        .container {{max-width:1400px;margin:auto}}
        .card {{background:white;border-radius:10px;padding:20px;margin:20px 0;box-shadow:0 5px 20px rgba(0,0,0,0.1)}}
        h1 {{color:#333;margin-bottom:10px}}
        h2 {{color:#555;margin-bottom:15px;border-bottom:2px solid #eee;padding-bottom:10px}}
        .grid {{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:20px}}
        .stat {{display:flex;justify-content:space-between;padding:10px 0;border-bottom:1px solid #eee}}
        .stat-label {{color:#666}}
        .stat-value {{font-weight:bold;color:#333}}
        .chart-container {{position:relative;height:300px;margin:20px 0}}
        table {{width:100%;border-collapse:collapse;margin-top:15px}}
        th {{background:#f5f5f5;padding:10px;text-align:left;border-bottom:2px solid #ddd}}
        td {{padding:8px;border-bottom:1px solid #eee}}
        tr:hover {{background:#f9f9f9}}
        .alert {{background:#fff3cd;color:#856404;padding:15px;border-radius:5px;margin:10px 0;border:1px solid #ffeaa7}}
        .alert-danger {{background:#f8d7da;color:#721c24;border-color:#f5c6cb}}
        .badge {{display:inline-block;padding:3px 8px;border-radius:3px;font-size:0.9em;font-weight:bold}}
        .badge-danger {{background:#dc3545;color:white}}
        .badge-warning {{background:#ffc107;color:#333}}
        .badge-success {{background:#28a745;color:white}}
        .badge-info {{background:#17a2b8;color:white}}
        code {{background:#f4f4f4;padding:2px 4px;border-radius:3px;font-family:monospace}}
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <h1>xsukax PCAP Analysis Report</h1>
            <p style="color:#666">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p style="color:#666">File: {report['metadata']['file']}</p>
        </div>
        
        <div class="grid">
            <div class="card">
                <h2>Overview</h2>
                <div class="stat">
                    <span class="stat-label">Total Packets</span>
                    <span class="stat-value">{report['summary']['packets']:,}</span>
                </div>
                <div class="stat">
                    <span class="stat-label">Total Bytes</span>
                    <span class="stat-value">{report['summary']['bytes']:,}</span>
                </div>
                <div class="stat">
                    <span class="stat-label">Bandwidth</span>
                    <span class="stat-value">{report['summary']['bandwidth_mbps']} Mbps</span>
                </div>
                <div class="stat">
                    <span class="stat-label">Unique IPs</span>
                    <span class="stat-value">{report['summary']['unique_ips']}</span>
                </div>
                <div class="stat">
                    <span class="stat-label">Security Threats</span>
                    <span class="stat-value">
                        <span class="badge {'badge-danger' if report['summary']['threats'] > 0 else 'badge-success'}">
                            {report['summary']['threats']}
                        </span>
                    </span>
                </div>
            </div>
            
            <div class="card">
                <h2>DNS Analysis</h2>
                <div class="stat">
                    <span class="stat-label">Total Queries</span>
                    <span class="stat-value">{report['dns_analysis']['summary']['queries']}</span>
                </div>
                <div class="stat">
                    <span class="stat-label">Unique Domains</span>
                    <span class="stat-value">{report['dns_analysis']['summary']['unique_domains']}</span>
                </div>
                <div class="stat">
                    <span class="stat-label">Suspicious Domains</span>
                    <span class="stat-value">
                        <span class="badge {'badge-warning' if report['dns_analysis']['summary']['suspicious'] > 0 else 'badge-success'}">
                            {report['dns_analysis']['summary']['suspicious']}
                        </span>
                    </span>
                </div>
                <div class="stat">
                    <span class="stat-label">NXDOMAIN</span>
                    <span class="stat-value">{report['dns_analysis']['summary']['nxdomain']}</span>
                </div>
                <div class="stat">
                    <span class="stat-label">DNS Servers</span>
                    <span class="stat-value">{len(report['dns_analysis']['summary']['servers'])}</span>
                </div>
            </div>
            
            <div class="card">
                <h2>Protocol Distribution</h2>
                <div class="chart-container">
                    <canvas id="protocolChart"></canvas>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h2>Top DNS Queries</h2>
            <table>
                <thead>
                    <tr>
                        <th>Domain</th>
                        <th>Count</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join([f'<tr><td><code>{d}</code></td><td>{c}</td></tr>' for d, c in list(report['dns_analysis']['top_queries'].items())[:200]])}
                </tbody>
            </table>
        </div>
        
        {f'''<div class="card">
            <h2>Security Threats</h2>
            {''.join([f'<div class="alert alert-danger"><strong>{t["type"]}</strong>: {t["details"]}</div>' for t in report['security']['threats'][:10]])}
        </div>''' if report['security']['threats'] else ''}
        
        <div class="card">
            <h2>DNS Query Types</h2>
            <div class="chart-container">
                <canvas id="dnsTypesChart"></canvas>
            </div>
        </div>
        
        <div class="card">
            <h2>Top Conversations</h2>
            <table>
                <thead>
                    <tr>
                        <th>Conversation</th>
                        <th>Packets</th>
                        <th>Bytes</th>
                        <th>Protocols</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join([f'<tr><td><code>{c[0]}</code></td><td>{c[1]}</td><td>{c[2]}</td><td>{", ".join(c[3])}</td></tr>' for c in report['conversations']['top'][:100]])}
                </tbody>
            </table>
        </div>
        
        <div class="card">
            <h2>Detected Services</h2>
            <table>
                <thead>
                    <tr>
                        <th>Service</th>
                        <th>Hosts</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join([f'<tr><td>{s}</td><td>{", ".join(h[:3])}{" ..." if len(h) > 3 else ""}</td></tr>' for s, h in list(report['services']['detected'].items())[:15]])}
                </tbody>
            </table>
        </div>
        
        <div class="card">
            <h2>Top Ports</h2>
            <table>
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Count</th>
                        <th>Service</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join([f'<tr><td>{p[0]}</td><td>{p[1]}</td><td>{p[2]}</td></tr>' for p in report['services']['ports'][:15]])}
                </tbody>
            </table>
        </div>
        
        {'<div class="card"><h2>Suspicious DNS Domains</h2><ul>' + ''.join([f'<li><code>{d}</code></li>' for d in report['dns_analysis']['suspicious_domains']]) + '</ul></div>' if report['dns_analysis']['suspicious_domains'] else ''}
        
        <div class="card">
            <h2>Packet Statistics</h2>
            <div class="stat">
                <span class="stat-label">Minimum Size</span>
                <span class="stat-value">{report['packet_stats']['sizes']['min']} bytes</span>
            </div>
            <div class="stat">
                <span class="stat-label">Maximum Size</span>
                <span class="stat-value">{report['packet_stats']['sizes']['max']} bytes</span>
            </div>
            <div class="stat">
                <span class="stat-label">Average Size</span>
                <span class="stat-value">{report['packet_stats']['sizes']['avg']} bytes</span>
            </div>
            <div class="stat">
                <span class="stat-label">Median Size</span>
                <span class="stat-value">{report['packet_stats']['sizes']['median']} bytes</span>
            </div>
        </div>
    </div>
    
    <script>
        // Protocol Distribution Chart
        const protocolCtx = document.getElementById('protocolChart').getContext('2d');
        const protocolData = {json.dumps({k: v['count'] for k, v in report['protocols'].items() if v['count'] > 0})};
        new Chart(protocolCtx, {{
            type: 'doughnut',
            data: {{
                labels: Object.keys(protocolData),
                datasets: [{{
                    data: Object.values(protocolData),
                    backgroundColor: [
                        '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF',
                        '#FF9F40', '#FF6384', '#C9CBCF', '#4BC0C0', '#FF6384'
                    ]
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        position: 'right'
                    }}
                }}
            }}
        }});
        
        // DNS Types Chart
        const dnsCtx = document.getElementById('dnsTypesChart').getContext('2d');
        const dnsData = {json.dumps(report['dns_analysis']['query_types'])};
        new Chart(dnsCtx, {{
            type: 'bar',
            data: {{
                labels: Object.keys(dnsData),
                datasets: [{{
                    label: 'Query Count',
                    data: Object.values(dnsData),
                    backgroundColor: '#36A2EB'
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                scales: {{
                    y: {{
                        beginAtZero: true
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"HTML: {output_file}")
    
    def export_markdown(self, report: Dict, output_file: str):
        """Export report as Markdown"""
        md = f"""# xsukax PCAP Analysis Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**File:** {report['metadata']['file']}  
**Analysis Duration:** {report['metadata']['analysis_duration']}s  
**Capture Duration:** {report['metadata']['capture_duration']}s

## Summary

| Metric | Value |
|--------|-------|
| Total Packets | {report['summary']['packets']:,} |
| Total Bytes | {report['summary']['bytes']:,} |
| Bandwidth | {report['summary']['bandwidth_mbps']} Mbps |
| Unique IPs | {report['summary']['unique_ips']} |
| Conversations | {report['summary']['conversations']} |
| Detected Services | {report['summary']['services']} |
| Security Threats | {report['summary']['threats']} |

## DNS Analysis

### Summary
- **Total Queries:** {report['dns_analysis']['summary']['queries']}
- **Unique Domains:** {report['dns_analysis']['summary']['unique_domains']}
- **Suspicious Domains:** {report['dns_analysis']['summary']['suspicious']}
- **NXDOMAIN Responses:** {report['dns_analysis']['summary']['nxdomain']}
- **DNS Servers:** {', '.join(report['dns_analysis']['summary']['servers']) if report['dns_analysis']['summary']['servers'] else 'None identified'}

### Query Types Distribution
```mermaid
pie title DNS Query Types
{chr(10).join([f'    "{t}" : {c}' for t, c in report['dns_analysis']['query_types'].items()])}
```

### Response Codes
```mermaid
pie title DNS Response Codes
{chr(10).join([f'    "{code}" : {count}' for code, count in report['dns_analysis']['response_codes'].items()])}
```

### Top 200 Queried Domains
| Rank | Domain | Count |
|------|--------|-------|
{chr(10).join([f'| {i+1} | `{d}` | {c} |' for i, (d, c) in enumerate(list(report['dns_analysis']['top_queries'].items())[:200])])}

### Suspicious Domains
{chr(10).join([f'- `{d}`' for d in report['dns_analysis']['suspicious_domains']]) if report['dns_analysis']['suspicious_domains'] else 'None detected'}

### NXDOMAIN Queries
{chr(10).join([f'- `{d}`' for d in report['dns_analysis']['nxdomain_queries'][:10]]) if report['dns_analysis']['nxdomain_queries'] else 'None'}

## Protocol Distribution

```mermaid
pie title Protocol Distribution
{chr(10).join([f'    "{p}" : {d["percent"]}' for p, d in report['protocols'].items() if d['count'] > 0])}
```

## Top Talkers

### By Packets
| IP Address | Packet Count |
|------------|--------------|
{chr(10).join([f'| {ip} | {count} |' for ip, count in report['top_talkers']['by_packets']])}

### By Bytes
| IP Address | Bytes |
|------------|-------|
{chr(10).join([f'| {ip} | {bytes} |' for ip, bytes in report['top_talkers']['by_bytes']])}

## Top Conversations
| Conversation | Packets | Bytes | Protocols |
|--------------|---------|-------|-----------|
{chr(10).join([f'| `{c[0]}` | {c[1]} | {c[2]} | {", ".join(c[3])} |' for c in report['conversations']['top']])}

## Services

### Detected Services
| Service | Hosts |
|---------|-------|
{chr(10).join([f'| {s} | {", ".join(h[:3])}{"..." if len(h) > 3 else ""} |' for s, h in report['services']['detected'].items()])}

### Top Ports
| Port | Count | Service |
|------|-------|---------|
{chr(10).join([f'| {p[0]} | {p[1]} | {p[2]} |' for p in report['services']['ports'][:20]])}

## TCP Flags Distribution
| Flag | Count |
|------|-------|
{chr(10).join([f'| {flag} | {count} |' for flag, count in report['tcp_flags'].items()])}

{'## HTTP Analysis' + chr(10) + chr(10) + '### Methods' + chr(10) + '| Method | Count |' + chr(10) + '|--------|-------|' + chr(10) + chr(10).join([f'| {m} | {c} |' for m, c in report['http']['methods'].items()]) + chr(10) + chr(10) + '### Status Codes' + chr(10) + '| Code | Count |' + chr(10) + '|------|-------|' + chr(10) + chr(10).join([f'| {code} | {count} |' for code, count in report['http']['status_codes'].items()]) + chr(10) + chr(10) + '### Top Hosts' + chr(10) + '| Host | Count |' + chr(10) + '|------|-------|' + chr(10) + chr(10).join([f'| {host} | {count} |' for host, count in report['http']['top_hosts'].items()]) if report['http'] else ''}

## Security Analysis

### Threat Summary
- **Total Threats:** {len(report['security']['threats'])}
- **Port Scans:** {len(report['security']['port_scans'])}
- **Malformed Packets:** {report['security']['malformed']}

### Detected Threats
{chr(10).join([f'- **{t["type"]}:** {t["details"]}' for t in report['security']['threats']]) if report['security']['threats'] else 'No threats detected'}

### Port Scan Details
{chr(10).join([f'- {s["ip"]}: {s["ports"]} ports accessed' for s in report['security']['port_scans']]) if report['security']['port_scans'] else 'No port scans detected'}

## Packet Statistics
- **Minimum Size:** {report['packet_stats']['sizes']['min']} bytes
- **Maximum Size:** {report['packet_stats']['sizes']['max']} bytes
- **Average Size:** {report['packet_stats']['sizes']['avg']} bytes
- **Median Size:** {report['packet_stats']['sizes']['median']} bytes

---
*Report generated by xsukax PCAP Analyzer v3.1*
"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(md)
        print(f"Markdown: {output_file}")
    
    def export_csv(self, report: Dict, output_dir: str):
        """Export report as CSV files"""
        import csv
        
        output_dir = Path(output_dir)
        output_dir.mkdir(exist_ok=True)
        
        # DNS queries CSV
        with open(output_dir / 'dns_queries.csv', 'w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow(['Domain', 'Count'])
            for d, c in report['dns_analysis']['top_queries'].items():
                w.writerow([d, c])
        
        # Conversations CSV
        with open(output_dir / 'conversations.csv', 'w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow(['Conversation', 'Packets', 'Bytes', 'Protocols'])
            for c in report['conversations']['top']:
                w.writerow([c[0], c[1], c[2], ', '.join(c[3])])
        
        # Services CSV
        with open(output_dir / 'services.csv', 'w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow(['Port', 'Count', 'Service'])
            for p in report['services']['ports']:
                w.writerow([p[0], p[1], p[2]])
        
        # Threats CSV
        with open(output_dir / 'threats.csv', 'w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow(['Type', 'Details'])
            for t in report['security']['threats']:
                w.writerow([t['type'], t['details']])
        
        print(f"CSV files: {output_dir}/")

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="xsukax PCAP Network Traffic Analyzer",
        epilog="Examples:\n"
               "  %(prog)s capture.pcap\n"
               "  %(prog)s capture.pcap --output all --level deep\n"
               "  %(prog)s capture.pcap -o html -d ./reports",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('pcap_file', help='PCAP file to analyze')
    parser.add_argument('-o', '--output', 
                       choices=['json', 'html', 'markdown', 'csv', 'all'],
                       default='markdown',
                       help='Output format (default: markdown)')
    parser.add_argument('-d', '--output-dir',
                       default='.',
                       help='Output directory (default: current)')
    parser.add_argument('-l', '--level',
                       choices=['basic', 'standard', 'deep', 'forensic'],
                       default='standard',
                       help='Analysis level (default: standard)')
    
    args = parser.parse_args()
    
    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)
    
    # Initialize analyzer
    analyzer = PCAPAnalyzer(args.level)
    
    try:
        # Perform analysis
        report = analyzer.analyze(args.pcap_file)
        
        # Generate outputs
        base = Path(args.pcap_file).stem
        
        if args.output in ['json', 'all']:
            analyzer.export_json(report, str(output_dir / f'{base}_analysis.json'))
        
        if args.output in ['html', 'all']:
            analyzer.export_html(report, str(output_dir / f'{base}_analysis.html'))
        
        if args.output in ['markdown', 'all']:
            analyzer.export_markdown(report, str(output_dir / f'{base}_analysis.md'))
        
        if args.output in ['csv', 'all']:
            analyzer.export_csv(report, str(output_dir / f'{base}_csv'))
        
        print(f"\nAnalysis complete! Reports saved to: {output_dir}/")
        return 0
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
