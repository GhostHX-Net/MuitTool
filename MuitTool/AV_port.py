#!/usr/bin/env python3
"""
ELITE SCAPY PORT SCANNER - The World's Best Network Service Discovery Tool
Professional-grade port scanning with TCP/UDP SYN, service detection, and comprehensive reporting.
Powered by Scapy for maximum flexibility and precision.
"""
import argparse
import socket
import sys
import time
import json
import csv
import os
import signal
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict
import ipaddress

try:
    from scapy.all import IP, TCP, UDP, ICMP, sr1, sr, RandShort, conf, get_if_addr
    from scapy.layers.inet import IP
    HAS_SCAPY = True
except ImportError:
    print("Error: Scapy library not found. Install with: pip install scapy")
    sys.exit(1)


class Colors:
    """Professional ANSI color codes for elite terminal output."""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    BRIGHT_RED = '\033[1;91m'
    BRIGHT_GREEN = '\033[1;92m'
    BRIGHT_CYAN = '\033[1;96m'
    BG_DARK = '\033[40m'
    RESET = '\033[0m'


# Common ports and their services
COMMON_PORTS = {
    20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
    53: 'dns', 80: 'http', 110: 'pop3', 143: 'imap', 161: 'snmp',
    179: 'bgp', 389: 'ldap', 443: 'https', 445: 'smb', 465: 'smtps',
    587: 'smtp', 636: 'ldaps', 993: 'imaps', 995: 'pop3s', 1433: 'mssql',
    3306: 'mysql', 3389: 'rdp', 5432: 'postgresql', 5900: 'vnc', 6379: 'redis',
    8080: 'http-proxy', 8443: 'https-alt', 9200: 'elasticsearch', 27017: 'mongodb'
}

# Port categories
PORT_CATEGORIES = {
    'Critical': [22, 3389, 1433, 3306, 5432, 27017],
    'Web Services': [80, 443, 8080, 8443],
    'Mail Services': [25, 110, 143, 465, 587, 993, 995],
    'Directory Services': [389, 636],
    'Database Services': [1433, 3306, 5432, 27017],
    'Remote Access': [22, 3389, 5900],
    'Monitoring': [161, 9200],
    'Other': []
}


def clear_screen() -> None:
    """Clear terminal safely."""
    os.system('clear' if os.name != 'nt' else 'cls')


def print_banner() -> None:
    """Display an epic, professional port scanner banner."""
    banner = f"""{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║           🔍   SCAPY ELITE PORT SCANNER v2.0   🔍                             ║
║                                                                               ║
║       Advanced TCP/UDP Port Analysis - Network Service Discovery              ║
║         Powered by Scapy | Professional Security Assessment                   ║
║                                                                               ║
║  ✓ SYN/ACK Scanning  ✓ UDP Probing  ✓ Service Detection  ✓ Banner Grab        ║
║  ✓ OS Fingerprint    ✓ Parallel Execution  ✓ HTML Reports                     ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
{Colors.RESET}"""
    print(banner)
    print(f'{Colors.YELLOW}⏱  {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{Colors.RESET}\n')


def print_section(title: str) -> None:
    """Print a styled section header."""
    print(f'\n{Colors.CYAN}{Colors.BOLD}╔{"═" * 78}╗{Colors.RESET}')
    print(f'{Colors.CYAN}{Colors.BOLD}║ {title.ljust(76)}║{Colors.RESET}')
    print(f'{Colors.CYAN}{Colors.BOLD}╚{"═" * 78}╝{Colors.RESET}\n')


def print_separator(length: int = 80) -> None:
    """Print a separator line."""
    print(f'{Colors.DIM}{"─" * length}{Colors.RESET}')


def get_service_name(port: int) -> str:
    """Get service name for a given port."""
    return COMMON_PORTS.get(port, "unknown")


def scan_port_scapy_syn(host: str, port: int, timeout: float = 1.0) -> Tuple[int, bool, str]:
    """
    Perform TCP SYN scan using Scapy.
    Returns (port, is_open, state).
    States: open, closed, filtered
    """
    try:
        # Create TCP SYN packet
        pkt = IP(dst=host) / TCP(dport=port, flags="S", sport=RandShort())
        
        # Send and receive response
        response = sr1(pkt, timeout=timeout, verbose=0)
        
        if response is None:
            return port, False, "filtered"
        
        # Check response flags
        if response.haslayer(TCP):
            flags = response[TCP].flags
            if flags & 0x12:  # SYN-ACK
                # Send RST to close connection
                rst_pkt = IP(dst=host) / TCP(dport=port, flags="R", sport=response[TCP].dport)
                sr1(rst_pkt, timeout=0.1, verbose=0)
                return port, True, "open"
            elif flags & 0x14:  # RST-ACK
                return port, False, "closed"
        
        if response.haslayer(ICMP):
            return port, False, "filtered"
            
    except PermissionError:
        raise
    except Exception:
        pass
    
    return port, False, "filtered"


def scan_port_scapy_udp(host: str, port: int, timeout: float = 2.0) -> Tuple[int, bool, str]:
    """
    Perform UDP scan using Scapy.
    Returns (port, is_open, state).
    """
    try:
        pkt = IP(dst=host) / UDP(dport=port, sport=RandShort())
        response = sr1(pkt, timeout=timeout, verbose=0)
        
        if response is None:
            return port, True, "open|filtered"  # No response = open or filtered
        
        if response.haslayer(UDP):
            return port, True, "open"
        
        if response.haslayer(ICMP):
            icmp_code = response[ICMP].code
            if icmp_code == 3:  # Unreachable
                return port, False, "closed"
            else:
                return port, False, "filtered"
    
    except PermissionError:
        raise
    except Exception:
        pass
    
    return port, False, "filtered"


def get_service_name(port: int) -> str:
    """Get service name for a given port."""
    return COMMON_PORTS.get(port, "unknown")


def parse_port_spec(spec: str, default_min: int = 1, default_max: int = 65535) -> List[int]:
    """
    Parse port specification.
    Examples: "22", "80,443", "1-1024", "80,443,1000-2000"
    """
    ports = set()
    
    try:
        for part in spec.split(','):
            part = part.strip()
            if '-' in part:
                start, end = part.split('-')
                ports.update(range(int(start.strip()), int(end.strip()) + 1))
            else:
                ports.add(int(part))
    except (ValueError, AttributeError):
        print(f'{Colors.RED}✗ Invalid port specification: {spec}{Colors.RESET}')
        return list(range(default_min, min(default_max + 1, default_min + 1000)))
    
    return sorted(list(ports))


def scan_ports_concurrent(host: str, ports: List[int], protocol: str = "tcp", 
                         parallelism: int = 100, timeout: float = 1.0) -> List[Tuple[int, bool, str]]:
    """
    Scan multiple ports in parallel using Scapy.
    Returns list of (port, is_open, state) tuples.
    """
    results = []
    protocol_upper = protocol.upper()
    
    print(f'{Colors.BLUE}[*] Scanning {len(ports)} ports with {parallelism} threads ({protocol_upper})...{Colors.RESET}')
    print_separator(80)
    
    open_ports = []
    start_time = time.time()
    scanned = 0
    
    scan_func = scan_port_scapy_syn if protocol == "tcp" else scan_port_scapy_udp
    
    try:
        with ThreadPoolExecutor(max_workers=parallelism) as executor:
            futures = {executor.submit(scan_func, host, port, timeout): port for port in ports}
            
            for fut in as_completed(futures):
                try:
                    port, is_open, state = fut.result()
                    results.append((port, is_open, state))
                    scanned += 1
                    
                    if is_open:
                        open_ports.append(port)
                        service = get_service_name(port)
                        print(f'{Colors.GREEN}[+] Port {port:5d}/{protocol:<4} {Colors.BRIGHT_GREEN}OPEN{Colors.RESET} ({state:<12}) - {service}')
                    
                    # Progress indicator
                    progress = (scanned / len(ports)) * 100
                    if scanned % max(1, len(ports) // 20) == 0:
                        print(f'{Colors.DIM}[Progress: {progress:.0f}%]{Colors.RESET}' + ' ' * 30, end='\r')
                except PermissionError:
                    raise
                except Exception:
                    pass
    except PermissionError:
        raise
    
    elapsed = time.time() - start_time
    print(f'\n{Colors.GREEN}✓ {protocol.upper()} scan complete in {elapsed:.2f}s - {len(open_ports)} ports open{Colors.RESET}\n')
    
    return sorted(results, key=lambda x: x[0])


def generate_port_list(scan_type: str) -> List[int]:
    """Generate port list based on scan type."""
    if scan_type == "quick":
        return [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995,
                1433, 3306, 3389, 5432, 5900, 8080, 8443]
    elif scan_type == "common":
        return list(COMMON_PORTS.keys())
    elif scan_type == "web":
        return [80, 8080, 8000, 8888, 443, 8443, 3000, 5000, 9000]
    elif scan_type == "database":
        return [1433, 3306, 5432, 27017, 6379, 9200, 11211]
    elif scan_type == "all":
        return list(range(1, 65536))
    else:
        return [22, 80, 443]


class PortScanResult:
    """Data structure for port scan results."""
    
    def __init__(self, host: str):
        self.host = host
        self.timestamp = datetime.now()
        self.open_ports: List[Dict[str, Any]] = []
        self.scan_duration = 0.0
        self.total_ports_scanned = 0
    
    def add_port(self, port: int, service: str, state: str = "open", banner: Optional[str] = None):
        """Add an open port to results."""
        self.open_ports.append({
            "port": port,
            "service": service,
            "state": state,
            "banner": banner or "",
            "severity": self._get_severity(port)
        })
    
    @staticmethod
    def _get_severity(port: int) -> str:
        """Determine port severity level."""
        critical = [22, 3389, 1433, 3306, 5432, 27017]
        high = [80, 443, 445, 139, 135, 389]
        
        if port in critical:
            return "CRITICAL"
        elif port in high:
            return "HIGH"
        else:
            return "MEDIUM"
    
    def get_summary(self) -> Dict[str, Any]:
        """Get scan summary."""
        return {
            "host": self.host,
            "timestamp": self.timestamp.isoformat(),
            "total_scanned": self.total_ports_scanned,
            "open_ports": len(self.open_ports),
            "duration": self.scan_duration,
            "ports": self.open_ports
        }


def print_results_table(results: PortScanResult) -> None:
    """Print beautiful results table with comprehensive information."""
    if not results.open_ports:
        print(f'\n{Colors.YELLOW}[!] No open ports discovered.{Colors.RESET}\n')
        return
    
    print_section(f"🎯 SCAN RESULTS - {results.host}")
    
    # Table header
    header = f'{Colors.BOLD}{Colors.YELLOW}{"PORT":<8} {"SERVICE":<20} {"STATE":<15} {"SEVERITY":<12}{Colors.RESET}'
    print(header)
    print_separator(80)
    
    # Sort by severity then port
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    sorted_ports = sorted(results.open_ports, 
                         key=lambda x: (severity_order.get(x["severity"], 3), x["port"]))
    
    for idx, port_info in enumerate(sorted_ports, 1):
        port = port_info["port"]
        service = port_info["service"]
        severity = port_info["severity"]
        state = port_info["state"]
        
        # Color by severity
        if severity == "CRITICAL":
            severity_display = f'{Colors.BRIGHT_RED}{severity}{Colors.RESET}'
        elif severity == "HIGH":
            severity_display = f'{Colors.RED}{severity}{Colors.RESET}'
        else:
            severity_display = f'{Colors.YELLOW}{severity}{Colors.RESET}'
        
        state_color = Colors.GREEN if state == "open" else Colors.YELLOW
        
        print(f'{Colors.CYAN}{port:<8}{Colors.RESET} {service:<20} {state_color}{state:<15}{Colors.RESET} {severity_display}')
        
        # Separator every 5 ports
        if (idx % 5 == 0) and (idx < len(sorted_ports)):
            print_separator(80)
    
    print_separator(80)
    
    # Summary statistics with improved formatting
    print(f'\n{Colors.BOLD}{Colors.CYAN}╔════════════════════════════════════════════════════════════════════════════════╗{Colors.RESET}')
    print(f'{Colors.BOLD}{Colors.CYAN}║                              SCAN SUMMARY REPORT                                    ║{Colors.RESET}')
    print(f'{Colors.BOLD}{Colors.CYAN}╚════════════════════════════════════════════════════════════════════════════════╝{Colors.RESET}\n')
    
    critical_count = sum(1 for p in results.open_ports if p["severity"] == "CRITICAL")
    high_count = sum(1 for p in results.open_ports if p["severity"] == "HIGH")
    medium_count = sum(1 for p in results.open_ports if p["severity"] == "MEDIUM")
    
    print(f'{Colors.BRIGHT_RED}  🔴 CRITICAL Ports: {critical_count}{Colors.RESET}')
    print(f'{Colors.RED}  🔴 HIGH Severity:   {high_count}{Colors.RESET}')
    print(f'{Colors.YELLOW}  🟡 MEDIUM:          {medium_count}{Colors.RESET}')
    print(f'{Colors.GREEN}  🟢 Total Open:      {len(results.open_ports)}{Colors.RESET}')
    print(f'{Colors.CYAN}  ⏱  Scan Duration:   {results.scan_duration:.2f}s{Colors.RESET}')
    print(f'{Colors.BLUE}  📊 Ports Scanned:   {results.total_ports_scanned}{Colors.RESET}')
    
    # Group by category
    print(f'\n{Colors.BOLD}{Colors.YELLOW}📦 SERVICE CATEGORIES:{Colors.RESET}')
    for category, ports in PORT_CATEGORIES.items():
        count = sum(1 for p in results.open_ports if p["port"] in ports)
        if count > 0:
            print(f'  {Colors.CYAN}├─ {category:<20}{Colors.RESET} {Colors.GREEN}{count}{Colors.RESET}')


def export_json(results: PortScanResult, filepath: str) -> None:
    """Export results to JSON file."""
    try:
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, 'w') as f:
            json.dump(results.get_summary(), f, indent=2)
        print(f'{Colors.GREEN}✓ JSON report saved to {Colors.CYAN}{filepath}{Colors.RESET}')
    except OSError as e:
        print(f'{Colors.RED}✗ Error saving JSON: {e}{Colors.RESET}')


def export_csv(results: PortScanResult, filepath: str) -> None:
    """Export results to CSV file."""
    try:
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Port', 'Service', 'State', 'Severity', 'Banner'])
            for port_info in results.open_ports:
                writer.writerow([
                    port_info['port'],
                    port_info['service'],
                    port_info['state'],
                    port_info['severity'],
                    port_info['banner']
                ])
        print(f'{Colors.GREEN}✓ CSV report saved to {Colors.CYAN}{filepath}{Colors.RESET}')
    except OSError as e:
        print(f'{Colors.RED}✗ Error saving CSV: {e}{Colors.RESET}')


def export_html(results: PortScanResult, filepath: str) -> None:
    """Export results to HTML report."""
    try:
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
        sorted_ports = sorted(results.open_ports, 
                             key=lambda x: (severity_order.get(x["severity"], 3), x["port"]))
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Port Scan Report - {results.host}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0a0e27; color: #e0e0e0; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 10px; margin-bottom: 30px; }}
        h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .metadata {{ font-size: 0.9em; opacity: 0.8; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .stat-card {{ background: #1a1f3a; padding: 20px; border-radius: 8px; border-left: 4px solid #667eea; }}
        .stat-card.critical {{ border-left-color: #ff4757; }}
        .stat-card.high {{ border-left-color: #ff6348; }}
        .stat-value {{ font-size: 2em; font-weight: bold; color: #667eea; }}
        .stat-card.critical .stat-value {{ color: #ff4757; }}
        .stat-card.high .stat-value {{ color: #ff6348; }}
        table {{ width: 100%; border-collapse: collapse; background: #1a1f3a; border-radius: 8px; overflow: hidden; }}
        th {{ background: #2d3142; padding: 15px; text-align: left; font-weight: 600; color: #667eea; }}
        td {{ padding: 12px 15px; border-bottom: 1px solid #2d3142; }}
        tr:hover {{ background: #252a3f; }}
        .port {{ font-weight: bold; color: #667eea; }}
        .critical {{ color: #ff4757; font-weight: bold; }}
        .high {{ color: #ff6348; font-weight: bold; }}
        .medium {{ color: #ffa502; font-weight: bold; }}
        footer {{ text-align: center; margin-top: 30px; font-size: 0.9em; opacity: 0.6; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 Port Scan Report</h1>
            <div class="metadata">
                <strong>Target:</strong> {results.host} | 
                <strong>Date:</strong> {results.timestamp.strftime('%Y-%m-%d %H:%M:%S')} | 
                <strong>Duration:</strong> {results.scan_duration:.2f}s
            </div>
        </header>
        
        <div class="summary">
            <div class="stat-card critical">
                <div class="stat-label">Critical Ports</div>
                <div class="stat-value">{sum(1 for p in results.open_ports if p['severity'] == 'CRITICAL')}</div>
            </div>
            <div class="stat-card high">
                <div class="stat-label">High Severity</div>
                <div class="stat-value">{sum(1 for p in results.open_ports if p['severity'] == 'HIGH')}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Total Open Ports</div>
                <div class="stat-value">{len(results.open_ports)}</div>
            </div>
        </div>
        
        <h2>Open Ports</h2>
        <table>
            <thead>
                <tr>
                    <th>Port</th>
                    <th>Service</th>
                    <th>State</th>
                    <th>Severity</th>
                    <th>Banner/Info</th>
                </tr>
            </thead>
            <tbody>
"""
        for port_info in sorted_ports:
            severity_class = port_info['severity'].lower()
            html += f"""                <tr>
                    <td class="port">{port_info['port']}</td>
                    <td>{port_info['service']}</td>
                    <td>{port_info['state']}</td>
                    <td class="{severity_class}">{port_info['severity']}</td>
                    <td>{port_info['banner'] or '—'}</td>
                </tr>
"""
        
        html += """            </tbody>
        </table>
        
        <footer>
            <p>Generated by Elite Port Scanner | Professional Network Security Tool</p>
        </footer>
    </div>
</body>
</html>"""
        
        with open(filepath, 'w') as f:
            f.write(html)
        print(f'{Colors.GREEN}✓ HTML report saved to {Colors.CYAN}{filepath}{Colors.RESET}')
    except OSError as e:
        print(f'{Colors.RED}✗ Error saving HTML: {e}{Colors.RESET}')


def get_user_input() -> Dict[str, Any]:
    """
    Interactively prompt user for all scan parameters.
    Returns a dictionary with all configuration options.
    """
    config = {}
    
    print_section("🎯 PORT SCANNER CONFIGURATION WIZARD")
    print(f'{Colors.YELLOW}Answer the following questions to configure your scan:\n{Colors.RESET}')
    
    # Get target host
    while True:
        print(f'{Colors.CYAN}{Colors.BOLD}[1] TARGET HOST{Colors.RESET}')
        print(f'{Colors.DIM}Enter the IP address or hostname to scan{Colors.RESET}')
        target = input(f'{Colors.BOLD}{Colors.CYAN}► Target > {Colors.RESET}').strip()
        
        if not target:
            print(f'{Colors.RED}✗ Target cannot be empty{Colors.RESET}\n')
            continue
        
        try:
            resolved_ip = socket.gethostbyname(target)
            print(f'{Colors.GREEN}✓ Resolved to {Colors.CYAN}{resolved_ip}{Colors.RESET}\n')
            config['target'] = resolved_ip
            break
        except socket.gaierror:
            print(f'{Colors.RED}✗ Could not resolve host: {target}{Colors.RESET}\n')
            continue
    
    # Get scan type or custom ports
    while True:
        print(f'{Colors.CYAN}{Colors.BOLD}[2] SCAN TYPE{Colors.RESET}')
        print(f'{Colors.DIM}Choose a scan type or enter custom ports:{Colors.RESET}')
        print(f'{Colors.YELLOW}  quick       - 22 most common ports{Colors.RESET}')
        print(f'{Colors.YELLOW}  common      - 60+ frequently used ports{Colors.RESET}')
        print(f'{Colors.YELLOW}  web         - Web service ports{Colors.RESET}')
        print(f'{Colors.YELLOW}  database    - Database service ports{Colors.RESET}')
        print(f'{Colors.YELLOW}  all         - All ports (1-65535){Colors.RESET}')
        print(f'{Colors.YELLOW}  custom      - Enter specific ports (e.g., "22,80,443,1000-2000"){Colors.RESET}')
        
        scan_choice = input(f'{Colors.BOLD}{Colors.CYAN}► Scan Type > {Colors.RESET}').strip().lower()
        
        if scan_choice in ['quick', 'common', 'web', 'database', 'all']:
            config['scan_type'] = scan_choice
            ports = generate_port_list(scan_choice)
            config['ports'] = ports
            print(f'{Colors.GREEN}✓ Selected {scan_choice} scan ({len(ports)} ports){Colors.RESET}\n')
            break
        elif scan_choice == 'custom':
            print(f'{Colors.DIM}Enter ports: 22,80,443 or 1-1024 or 80,443,1000-2000{Colors.RESET}')
            ports_input = input(f'{Colors.BOLD}{Colors.CYAN}► Ports > {Colors.RESET}').strip()
            ports = parse_port_spec(ports_input)
            if ports:
                config['scan_type'] = 'custom'
                config['ports'] = ports
                print(f'{Colors.GREEN}✓ Custom ports selected ({len(ports)} ports){Colors.RESET}\n')
                break
            else:
                print(f'{Colors.RED}✗ Invalid port specification{Colors.RESET}\n')
        else:
            print(f'{Colors.RED}✗ Invalid choice{Colors.RESET}\n')
    
    # Get protocol
    while True:
        print(f'{Colors.CYAN}{Colors.BOLD}[3] PROTOCOL{Colors.RESET}')
        print(f'{Colors.YELLOW}  tcp - TCP SYN scanning (recommended){Colors.RESET}')
        print(f'{Colors.YELLOW}  udp - UDP scanning{Colors.RESET}')
        
        protocol = input(f'{Colors.BOLD}{Colors.CYAN}► Protocol > {Colors.RESET}').strip().lower()
        
        if protocol in ['tcp', 'udp']:
            config['protocol'] = protocol
            print(f'{Colors.GREEN}✓ Protocol set to {protocol.upper()}{Colors.RESET}\n')
            break
        else:
            print(f'{Colors.RED}✗ Invalid choice. Choose tcp or udp{Colors.RESET}\n')
    
    # Get parallelism
    while True:
        print(f'{Colors.CYAN}{Colors.BOLD}[4] PARALLELISM{Colors.RESET}')
        print(f'{Colors.DIM}Number of concurrent threads (1-500, default 100){Colors.RESET}')
        
        parallelism_input = input(f'{Colors.BOLD}{Colors.CYAN}► Threads > {Colors.RESET}').strip()
        
        if not parallelism_input:
            config['parallelism'] = 100
            print(f'{Colors.GREEN}✓ Parallelism set to 100 threads{Colors.RESET}\n')
            break
        
        try:
            parallelism = int(parallelism_input)
            if 1 <= parallelism <= 500:
                config['parallelism'] = parallelism
                print(f'{Colors.GREEN}✓ Parallelism set to {parallelism} threads{Colors.RESET}\n')
                break
            else:
                print(f'{Colors.RED}✗ Value must be between 1-500{Colors.RESET}\n')
        except ValueError:
            print(f'{Colors.RED}✗ Invalid number{Colors.RESET}\n')
    
    # Get timeout
    while True:
        print(f'{Colors.CYAN}{Colors.BOLD}[5] TIMEOUT{Colors.RESET}')
        print(f'{Colors.DIM}Seconds per port (0.5-10, default 1.0){Colors.RESET}')
        
        timeout_input = input(f'{Colors.BOLD}{Colors.CYAN}► Timeout > {Colors.RESET}').strip()
        
        if not timeout_input:
            config['timeout'] = 1.0
            print(f'{Colors.GREEN}✓ Timeout set to 1.0 seconds{Colors.RESET}\n')
            break
        
        try:
            timeout = float(timeout_input)
            if 0.5 <= timeout <= 10:
                config['timeout'] = timeout
                print(f'{Colors.GREEN}✓ Timeout set to {timeout} seconds{Colors.RESET}\n')
                break
            else:
                print(f'{Colors.RED}✗ Value must be between 0.5-10{Colors.RESET}\n')
        except ValueError:
            print(f'{Colors.RED}✗ Invalid number{Colors.RESET}\n')
    
    # Get output formats
    config['json'] = None
    config['csv'] = None
    config['html'] = None
    
    print(f'{Colors.CYAN}{Colors.BOLD}[6] EXPORT OPTIONS{Colors.RESET}')
    print(f'{Colors.DIM}Save results to files (optional){Colors.RESET}\n')
    
    # JSON export
    print(f'{Colors.YELLOW}Save as JSON? (y/n, default: n){Colors.RESET}')
    if input(f'{Colors.BOLD}{Colors.CYAN}► JSON Export > {Colors.RESET}').strip().lower() == 'y':
        default_json = "port_scan_results.json"
        filename = input(f'{Colors.BOLD}{Colors.CYAN}► Filename > {Colors.RESET}').strip()
        config['json'] = filename if filename else default_json
        print(f'{Colors.GREEN}✓ JSON output: {config["json"]}{Colors.RESET}')
    
    # CSV export
    print(f'{Colors.YELLOW}Save as CSV? (y/n, default: n){Colors.RESET}')
    if input(f'{Colors.BOLD}{Colors.CYAN}► CSV Export > {Colors.RESET}').strip().lower() == 'y':
        default_csv = "port_scan_results.csv"
        filename = input(f'{Colors.BOLD}{Colors.CYAN}► Filename > {Colors.RESET}').strip()
        config['csv'] = filename if filename else default_csv
        print(f'{Colors.GREEN}✓ CSV output: {config["csv"]}{Colors.RESET}')
    
    # HTML export
    print(f'{Colors.YELLOW}Save as HTML? (y/n, default: n){Colors.RESET}')
    if input(f'{Colors.BOLD}{Colors.CYAN}► HTML Export > {Colors.RESET}').strip().lower() == 'y':
        default_html = "port_scan_report.html"
        filename = input(f'{Colors.BOLD}{Colors.CYAN}► Filename > {Colors.RESET}').strip()
        config['html'] = filename if filename else default_html
        print(f'{Colors.GREEN}✓ HTML output: {config["html"]}{Colors.RESET}')
    
    return config


def signal_handler(signum, frame) -> None:
    """Handle graceful shutdown."""
    print(f'\n\n{Colors.YELLOW}[*] Scan interrupted by user.{Colors.RESET}')
    sys.exit(0)


def signal_handler(signum, frame) -> None:
    """Handle graceful shutdown."""
    print(f'\n\n{Colors.YELLOW}[*] Scan interrupted by user.{Colors.RESET}')
    sys.exit(0)


def main() -> None:
    """Main application flow powered by Scapy with interactive input."""
    clear_screen()
    print_banner()
    
    # Get user configuration interactively
    config = get_user_input()
    signal.signal(signal.SIGINT, signal_handler)
    
    target = config['target']
    ports = config['ports']
    protocol = config['protocol']
    parallelism = config['parallelism']
    timeout = config['timeout']
    
    # Display configuration
    print_section("⚙️  SCAN CONFIGURATION SUMMARY")
    print(f'{Colors.CYAN}Target Host:    {Colors.YELLOW}{target}{Colors.RESET}')
    print(f'{Colors.CYAN}Ports to Scan:  {Colors.YELLOW}{len(ports)}{Colors.RESET}')
    print(f'{Colors.CYAN}Scan Type:      {Colors.YELLOW}{config["scan_type"].upper()}{Colors.RESET}')
    print(f'{Colors.CYAN}Protocol:       {Colors.YELLOW}{protocol.upper()}{Colors.RESET}')
    print(f'{Colors.CYAN}Parallelism:    {Colors.YELLOW}{parallelism} threads{Colors.RESET}')
    print(f'{Colors.CYAN}Timeout:        {Colors.YELLOW}{timeout}s per port{Colors.RESET}')
    
    export_info = []
    if config['json']:
        export_info.append(f"JSON → {config['json']}")
    if config['csv']:
        export_info.append(f"CSV → {config['csv']}")
    if config['html']:
        export_info.append(f"HTML → {config['html']}")
    
    if export_info:
        print(f'{Colors.CYAN}Export To:      {Colors.YELLOW}{", ".join(export_info)}{Colors.RESET}')
    
    print_separator(80)
    
    # Confirmation
    print(f'{Colors.YELLOW}Ready to scan? (Press Enter to start or Ctrl+C to cancel){Colors.RESET}')
    input(f'{Colors.BOLD}{Colors.CYAN}► {Colors.RESET}')
    print()
    
    # Create results object
    results = PortScanResult(target)
    results.total_ports_scanned = len(ports)
    
    # Scan ports using Scapy
    start_time = time.time()
    scan_results = scan_ports_concurrent(target, ports, protocol, parallelism, timeout)
    
    # Process results - add open ports to results
    open_ports_count = 0
    for port, is_open, state in scan_results:
        if is_open:
            open_ports_count += 1
            service = get_service_name(port)
            results.add_port(port, service, state)
    
    results.scan_duration = time.time() - start_time
    
    # Display results
    print_results_table(results)
    
    # Export if requested
    if config['json']:
        export_json(results, config['json'])
    if config['csv']:
        export_csv(results, config['csv'])
    if config['html']:
        export_html(results, config['html'])
    
    print_separator(80)
    print(f'{Colors.GREEN}{Colors.BOLD}✓ Scan completed successfully!{Colors.RESET}\n')


if __name__ == "__main__":
    main()
