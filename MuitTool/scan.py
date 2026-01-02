#!/usr/bin/env python3
"""
Advanced Network Scanner Tool
Comprehensive network discovery using ARP, ICMP, and reverse DNS with multiple output formats.
"""
import argparse
import csv
import ipaddress
import json
import os
import signal
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from io import StringIO
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

try:
    from scapy.all import (
        conf,
        get_if_addr,
        sr,
        srp,
        sr1,
        Ether,
        ARP,
        IP,
        ICMP,
    )
except ImportError as e:
    print("Error: Scapy library not found. Install with: pip install scapy", file=sys.stderr)
    print(f"Details: {e}", file=sys.stderr)
    sys.exit(1)


class Colors:
    """ANSI color codes for enhanced terminal output."""
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
    RESET = '\033[0m'


def clear_screen() -> None:
    """Clear terminal safely across platforms."""
    os.system('clear' if os.name != 'nt' else 'cls')


def print_header() -> None:
    """Display an impressive network scanner header."""
    header = f"""{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║         🌐  ADVANCED NETWORK SCANNER TOOL  🌐                 ║
║                                                               ║
║      IP & MAC Address Discovery, Enumeration & Analysis       ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
{Colors.RESET}"""
    print(header)
    print(f'{Colors.YELLOW}⏱  {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{Colors.RESET}\n')


def print_separator(length: int = 70) -> None:
    """Print a styled separator line."""
    print(f'{Colors.DIM}{"─" * length}{Colors.RESET}')


def detect_default_iface_and_network() -> Tuple[str, Optional[str], Optional[ipaddress.IPv4Network]]:
    """
    Automatically detect the default network interface and IP configuration.
    Returns tuple of (interface, ip_address, network).
    """
    iface = conf.iface
    ip = None
    
    try:
        ip = get_if_addr(iface)
        if not ip or ip == "0.0.0.0":
            raise Exception("no IP assigned")
    except Exception:
        try:
            route = conf.route.route("0.0.0.0")
            if route and len(route) >= 3:
                detected_iface = route[0] or iface
                detected_ip = route[1] or None
                iface = detected_iface or iface
                ip = detected_ip or ip
        except Exception:
            pass
    
    # Determine network from IP
    net = None
    if ip:
        try:
            net = ipaddress.ip_network(ip + "/24", strict=False)
        except Exception:
            pass
    
    return iface, ip, net


def prompt_for_network(detected_network: Optional[ipaddress.IPv4Network]) -> Optional[ipaddress.IPv4Network]:
    """
    Interactively prompt user for target network or IP.
    Returns parsed IPv4Network object.
    """
    if detected_network:
        print(f'{Colors.BLUE}Detected network: {Colors.CYAN}{detected_network}{Colors.RESET}')
    
    print(f'\n{Colors.YELLOW}╔═══════════════════════════════════════════════════════════╗{Colors.RESET}')
    print(f'{Colors.BOLD}{Colors.YELLOW}[?] Enter Target Network or IP Address{Colors.RESET}')
    print(f'{Colors.YELLOW}╚═══════════════════════════════════════════════════════════╝{Colors.RESET}')
    print(f'{Colors.DIM}Examples: 192.168.1.0/24, 10.0.0.0/16, 192.168.1.5{Colors.RESET}\n')

    try:
        user_input = input(f'{Colors.BOLD}{Colors.CYAN}► Network > {Colors.RESET}').strip()
    except (EOFError, KeyboardInterrupt):
        return detected_network

    if not user_input:
        if detected_network:
            print(f'{Colors.GREEN}✓ Using detected network{Colors.RESET}\n')
        return detected_network

    # Try parsing as network first, then as single IP
    try:
        net = ipaddress.ip_network(user_input, strict=False)
        print(f'{Colors.GREEN}✓ Network set to {Colors.CYAN}{net}{Colors.RESET}\n')
        return net
    except ValueError:
        try:
            ip_obj = ipaddress.ip_address(user_input)
            net = ipaddress.ip_network(str(ip_obj) + "/32", strict=False)
            print(f'{Colors.GREEN}✓ Single IP set to {Colors.CYAN}{ip_obj}{Colors.RESET}\n')
            return net
        except ValueError:
            print(f'{Colors.RED}✗ Invalid IP or network: {user_input}{Colors.RESET}')
            return None


def arp_scan(network: ipaddress.IPv4Network, iface: Optional[str] = None, timeout: float = 2.0) -> List[Tuple[str, str]]:
    """
    Perform ARP scan to discover active hosts on network.
    Uses layer 2 broadcasting for fast, reliable discovery.
    Returns list of (ip, mac) tuples.
    """
    target = str(network)
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)
    
    print(f'{Colors.BLUE}[*] Sending ARP requests...{Colors.RESET}')
    start_time = time.time()
    
    try:
        ans, _ = srp(pkt, timeout=timeout, iface=iface, verbose=0)
    except Exception as e:
        print(f'{Colors.RED}✗ ARP scan error: {e}{Colors.RESET}')
        return []
    
    elapsed = time.time() - start_time
    
    results = []
    for snd, rcv in ans:
        ip = getattr(rcv, "psrc", None)
        mac = getattr(rcv, "hwsrc", None)
        if ip:
            results.append((ip, mac or ""))
    
    # Sort by IP address for consistent output
    results.sort(key=lambda x: tuple(int(p) for p in x[0].split(".")))
    print(f'{Colors.GREEN}✓ ARP scan complete - {len(results)} hosts found in {elapsed:.2f}s{Colors.RESET}')
    
    return results


def icmp_ping_one(host: str, iface: Optional[str], timeout: float) -> Optional[str]:
    """
    Ping a single host using ICMP echo request (sr1).
    Returns host IP if reply received, None otherwise.
    """
    try:
        pkt = IP(dst=host) / ICMP()
        resp = sr1(pkt, timeout=timeout, iface=iface, verbose=0)
        if resp is not None:
            return host
    except PermissionError:
        raise
    except Exception:
        pass
    return None


def icmp_scan_concurrent(network: ipaddress.IPv4Network, iface: Optional[str], 
                         timeout: float = 1.0, parallelism: int = 100) -> List[str]:
    """
    Perform concurrent ICMP ping sweep across network.
    Uses thread pool for parallel scanning.
    Returns sorted list of responsive IP addresses.
    """
    hosts = [str(h) for h in network.hosts()]
    if not hosts:
        return []
    
    alive: Set[str] = set()
    print(f'{Colors.BLUE}[*] ICMP scanning {len(hosts)} hosts with {parallelism} threads...{Colors.RESET}')
    
    start_time = time.time()
    completed = 0
    
    try:
        with ThreadPoolExecutor(max_workers=parallelism) as executor:
            futures = {executor.submit(icmp_ping_one, host, iface, timeout): host for host in hosts}
            
            for fut in as_completed(futures):
                completed += 1
                try:
                    res = fut.result()
                    if res:
                        alive.add(res)
                        print(f'{Colors.GREEN}[+]{Colors.RESET} {Colors.CYAN}{res}{Colors.RESET} responding', end='\r')
                    
                    # Progress indicator every 10%
                    progress_pct = (completed / len(hosts)) * 100
                    if completed % max(1, len(hosts) // 10) == 0:
                        print(f'{Colors.DIM}[Progress: {progress_pct:.0f}%]{Colors.RESET}' + ' ' * 50, end='\r')
                except PermissionError:
                    raise
                except Exception:
                    pass
    except PermissionError:
        raise
    
    elapsed = time.time() - start_time
    alive_sorted = sorted(alive, key=lambda ip: tuple(int(p) for p in ip.split(".")))
    print(f'{Colors.GREEN}✓ ICMP scan complete - {len(alive_sorted)} hosts up in {elapsed:.2f}s{Colors.RESET}' + ' ' * 50)
    
    return alive_sorted


def reverse_dns_lookup(ip: str, timeout: float = 3.0) -> Optional[str]:
    """
    Perform reverse DNS lookup to resolve IP to hostname.
    Returns hostname string or None if lookup fails.
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def merge_results(arp: List[Tuple[str, str]], icmp: List[str], 
                 do_reverse: bool, parallelism: int = 20) -> List[Dict]:
    """
    Merge ARP and ICMP scan results into unified dataset.
    Optionally performs reverse DNS lookups in parallel.
    Returns list of dicts with ip, mac, seen_by, hostname.
    """
    data: Dict[str, Dict] = {}
    
    # Add ARP results
    for ip, mac in arp:
        data.setdefault(ip, {"ip": ip, "mac": "", "seen_by": set(), "hostname": ""})
        data[ip]["mac"] = mac
        data[ip]["seen_by"].add("arp")
    
    # Add ICMP results
    for ip in icmp:
        data.setdefault(ip, {"ip": ip, "mac": "", "seen_by": set(), "hostname": ""})
        data[ip]["seen_by"].add("icmp")

    # Perform reverse DNS lookups if requested
    ips = list(data.keys())
    if do_reverse and ips:
        print(f'{Colors.BLUE}[*] Performing reverse DNS lookups on {len(ips)} hosts...{Colors.RESET}')
        
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(3.0)
        
        try:
            with ThreadPoolExecutor(max_workers=parallelism) as executor:
                futures = {executor.submit(reverse_dns_lookup, ip): ip for ip in ips}
                
                for fut in as_completed(futures):
                    ip = futures[fut]
                    try:
                        hostname = fut.result()
                        if hostname:
                            data[ip]["hostname"] = hostname
                    except Exception:
                        pass
        finally:
            socket.setdefaulttimeout(old_timeout)
        
        print(f'{Colors.GREEN}✓ DNS lookups complete{Colors.RESET}')

    # Build final results list
    results = []
    for ip in sorted(data.keys(), key=lambda ip: tuple(int(p) for p in ip.split("."))):
        item = data[ip]
        results.append({
            "ip": item["ip"],
            "mac": item["mac"],
            "seen_by": sorted(list(item["seen_by"])),
            "hostname": item["hostname"] or ""
        })
    
    return results


def print_table(results: List[Dict]) -> None:
    """
    Print results in a beautifully formatted table with colors and statistics.
    Shows IP, MAC, hostname, and discovery method for each host.
    """
    if not results:
        print(f'\n{Colors.YELLOW}[!] No hosts discovered during scan.{Colors.RESET}\n')
        return
    
    print(f'\n{Colors.CYAN}{Colors.BOLD}╔═══════════════════════════════════════════════════════════════════════╗{Colors.RESET}')
    print(f'{Colors.CYAN}{Colors.BOLD}║                    SCAN RESULTS - DISCOVERED HOSTS                       ║{Colors.RESET}')
    print(f'{Colors.CYAN}{Colors.BOLD}╚═══════════════════════════════════════════════════════════════════════╝{Colors.RESET}\n')
    
    # Calculate column widths
    max_ip = max(len(r["ip"]) for r in results) if results else 0
    max_mac = max(len(r["mac"]) for r in results) if results else 0
    max_host = max(len(r["hostname"]) for r in results) if results else 0
    
    max_ip = max(max_ip, 15)
    max_mac = max(max_mac, 17)
    max_host = max(max_host, 25)
    
    # Print header
    header = f'{Colors.BOLD}{Colors.YELLOW}{"IP".ljust(max_ip)}  {"MAC ADDRESS".ljust(max_mac)}  {"HOSTNAME".ljust(max_host)}  METHOD{Colors.RESET}'
    print(header)
    print(f'{Colors.DIM}{"─" * (max_ip + 2 + max_mac + 2 + max_host + 2 + 10)}{Colors.RESET}')
    
    # Print each host
    for idx, result in enumerate(results, 1):
        ip = result["ip"]
        mac = result["mac"]
        hostname = result["hostname"]
        methods = ",".join(result["seen_by"])
        
        # Color code by detection method
        if len(result["seen_by"]) == 2:
            ip_color = Colors.GREEN  # Both ARP and ICMP
        elif "arp" in result["seen_by"]:
            ip_color = Colors.CYAN
        else:
            ip_color = Colors.BLUE
        
        # Format the row
        mac_display = mac if mac else f'{Colors.DIM}N/A{Colors.RESET}'
        hostname_display = hostname if hostname else f'{Colors.DIM}—{Colors.RESET}'
        
        print(f'{ip_color}{ip.ljust(max_ip)}{Colors.RESET}  {mac_display.ljust(max_mac)}  {hostname_display.ljust(max_host)}  {Colors.MAGENTA}{methods}{Colors.RESET}')
        
        # Add separator every 5 hosts for readability
        if (idx % 5 == 0) and (idx < len(results)):
            print(f'{Colors.DIM}{"─" * (max_ip + 2 + max_mac + 2 + max_host + 2 + 10)}{Colors.RESET}')
    
    print(f'\n{Colors.DIM}{"─" * (max_ip + 2 + max_mac + 2 + max_host + 2 + 10)}{Colors.RESET}')
    print(f'{Colors.GREEN}{Colors.BOLD}Total Hosts Discovered: {len(results)}{Colors.RESET}')
    
    # Summary statistics
    arp_count = sum(1 for r in results if "arp" in r["seen_by"])
    icmp_count = sum(1 for r in results if "icmp" in r["seen_by"])
    dns_count = sum(1 for r in results if r["hostname"])
    mac_count = sum(1 for r in results if r["mac"])
    
    print(f'{Colors.CYAN}├─ Found via ARP:    {arp_count}{Colors.RESET}')
    print(f'{Colors.CYAN}├─ Found via ICMP:   {icmp_count}{Colors.RESET}')
    print(f'{Colors.CYAN}├─ With MAC address: {mac_count}{Colors.RESET}')
    print(f'{Colors.CYAN}└─ With hostname:    {dns_count}{Colors.RESET}\n')


def write_json(path: str, results: List[Dict]) -> None:
    """Write results to JSON file."""
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({
                "scanned_at": datetime.utcnow().isoformat() + "Z",
                "host_count": len(results),
                "results": results
            }, f, indent=2)
    except OSError as e:
        print(f'{Colors.RED}✗ Error writing JSON: {e}{Colors.RESET}')


def write_csv(path: str, results: List[Dict]) -> None:
    """Write results to CSV file."""
    try:
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["IP Address", "MAC Address", "Hostname", "Discovery Method"])
            for r in results:
                writer.writerow([r["ip"], r["mac"], r["hostname"], ";".join(r["seen_by"])])
    except OSError as e:
        print(f'{Colors.RED}✗ Error writing CSV: {e}{Colors.RESET}')


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        prog="Network Scanner",
        description="Advanced network scanner using ARP, ICMP, and reverse DNS with multiple output formats",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -n 192.168.1.0/24 -m both -r
  %(prog)s --network 10.0.0.0/24 --method arp --output json -f results.json
  %(prog)s -i eth0 --reverse --output csv -f hosts.csv
        """
    )
    
    parser.add_argument("-n", "--network", 
                       help="Target network in CIDR (e.g., 192.168.1.0/24) or single IP")
    parser.add_argument("-i", "--iface", 
                       help="Network interface to use (default: auto-detect)")
    parser.add_argument("-m", "--method", 
                       choices=("arp", "icmp", "both"), 
                       default="arp",
                       help="Scan method: arp (default), icmp, or both")
    parser.add_argument("-t", "--timeout", 
                       type=float, 
                       help="Timeout for requests in seconds (auto-optimized if omitted)")
    parser.add_argument("-p", "--parallelism", 
                       type=int, 
                       default=100,
                       help="Parallel workers for ICMP and DNS (default 100)")
    parser.add_argument("-r", "--reverse", 
                       action="store_true",
                       help="Perform reverse DNS lookups on discovered IPs")
    parser.add_argument("-o", "--output", 
                       choices=("table", "json", "csv"), 
                       default="table",
                       help="Output format: table (default), json, or csv")
    parser.add_argument("-f", "--file", 
                       help="Save output to file (prints to stdout if omitted)")
    parser.add_argument("-q", "--quiet", 
                       action="store_true",
                       help="Suppress header and extra output")
    
    return parser.parse_args()


def signal_handler(signum, frame) -> None:
    """Handle SIGINT (Ctrl+C) for graceful shutdown."""
    print(f'\n\n{Colors.YELLOW}[*] Scan interrupted by user.{Colors.RESET}')
    sys.exit(0)


def main() -> None:
    """Main application entry point and control flow."""
    # Validate Scapy setup
    if not hasattr(conf, "route"):
        print(f'{Colors.RED}✗ Scapy configuration error. Is scapy installed correctly?{Colors.RESET}', 
              file=sys.stderr)
        sys.exit(1)

    clear_screen()
    print_header()
    
    # Parse arguments
    args = parse_args()
    iface = args.iface or conf.iface
    method = args.method
    timeout = args.timeout
    parallelism = max(1, args.parallelism)
    do_reverse = args.reverse

    # Determine target network
    network: Optional[ipaddress.IPv4Network] = None
    
    if args.network:
        try:
            network = ipaddress.ip_network(args.network, strict=False)
        except ValueError:
            try:
                ip_obj = ipaddress.ip_address(args.network)
                network = ipaddress.ip_network(str(ip_obj) + "/32", strict=False)
            except ValueError:
                print(f'{Colors.RED}✗ Invalid network or IP address: {args.network}{Colors.RESET}', 
                      file=sys.stderr)
                sys.exit(1)
    else:
        detected_iface, detected_ip, detected_net = detect_default_iface_and_network()
        iface = args.iface or detected_iface
        network = prompt_for_network(detected_net)
        
        if network is None:
            print(f'{Colors.RED}✗ No valid network provided.{Colors.RESET}', file=sys.stderr)
            sys.exit(1)

    # Display scan configuration
    print(f'{Colors.BOLD}{Colors.YELLOW}╔═══════════════════════════════════════════════════════════╗{Colors.RESET}')
    print(f'{Colors.BOLD}{Colors.YELLOW}[*] SCAN CONFIGURATION{Colors.RESET}')
    print(f'{Colors.BOLD}{Colors.YELLOW}╚═══════════════════════════════════════════════════════════╝{Colors.RESET}')
    print(f'   {Colors.CYAN}Network:{Colors.RESET}       {Colors.YELLOW}{network}{Colors.RESET}')
    print(f'   {Colors.CYAN}Interface:{Colors.RESET}     {Colors.YELLOW}{iface}{Colors.RESET}')
    print(f'   {Colors.CYAN}Method:{Colors.RESET}        {Colors.YELLOW}{method.upper()}{Colors.RESET}')
    if do_reverse:
        print(f'   {Colors.CYAN}Reverse DNS:{Colors.RESET}    {Colors.GREEN}Enabled{Colors.RESET}')
    print(f'{Colors.YELLOW}{"─" * 60}{Colors.RESET}\n')

    arp_results: List[Tuple[str, str]] = []
    icmp_results: List[str] = []
    
    # Register signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)

    try:
        # Run ARP scan
        if method in ("arp", "both"):
            arp_timeout = timeout if timeout is not None else 2.0
            arp_results = arp_scan(network, iface=iface, timeout=arp_timeout)

        # Run ICMP scan
        if method in ("icmp", "both"):
            icmp_timeout = timeout if timeout is not None else 1.0
            icmp_results = icmp_scan_concurrent(network, iface=iface, timeout=icmp_timeout, 
                                               parallelism=parallelism)

    except PermissionError:
        print(f'\n{Colors.RED}✗ Permission denied. Run with sudo.{Colors.RESET}', file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print(f'\n{Colors.YELLOW}[*] Scan interrupted by user.{Colors.RESET}')
        sys.exit(0)
    except Exception as e:
        print(f'{Colors.RED}✗ Scan error: {e}{Colors.RESET}', file=sys.stderr)
        sys.exit(1)

    # Merge and process results
    print(f'\n{Colors.BLUE}[*] Merging results...{Colors.RESET}')
    merged = merge_results(arp_results, icmp_results, do_reverse, 
                          parallelism=min(20, parallelism))

    print_separator(70)
    
    # Output results based on format
    if args.output == "table":
        buf = StringIO()
        old_stdout = sys.stdout
        try:
            sys.stdout = buf
            print_table(merged)
            output_text = buf.getvalue()
        finally:
            sys.stdout = old_stdout
            buf.close()

        if args.file:
            try:
                Path(args.file).parent.mkdir(parents=True, exist_ok=True)
                with open(args.file, "w", encoding="utf-8") as f:
                    f.write(output_text)
                print(f'{Colors.GREEN}✓ Results written to {Colors.CYAN}{args.file}{Colors.RESET}')
            except OSError as e:
                print(f'{Colors.RED}✗ Error writing file: {e}{Colors.RESET}')
        else:
            print(output_text.rstrip("\n"))

    elif args.output == "json":
        if args.file:
            try:
                Path(args.file).parent.mkdir(parents=True, exist_ok=True)
                write_json(args.file, merged)
                print(f'{Colors.GREEN}✓ JSON results written to {Colors.CYAN}{args.file}{Colors.RESET}')
            except OSError as e:
                print(f'{Colors.RED}✗ Error writing file: {e}{Colors.RESET}')
        else:
            json_output = json.dumps({
                "scanned_at": datetime.utcnow().isoformat() + "Z",
                "host_count": len(merged),
                "results": merged
            }, indent=2)
            print(json_output)

    elif args.output == "csv":
        if args.file:
            try:
                Path(args.file).parent.mkdir(parents=True, exist_ok=True)
                write_csv(args.file, merged)
                print(f'{Colors.GREEN}✓ CSV results written to {Colors.CYAN}{args.file}{Colors.RESET}')
            except OSError as e:
                print(f'{Colors.RED}✗ Error writing file: {e}{Colors.RESET}')
        else:
            import io
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(["IP Address", "MAC Address", "Hostname", "Discovery Method"])
            for r in merged:
                writer.writerow([r["ip"], r["mac"], r["hostname"], ";".join(r["seen_by"])])
            print(buf.getvalue().rstrip("\n"))

    print(f'\n{Colors.DIM}{"─" * 70}{Colors.RESET}')
    print(f'{Colors.GREEN}{Colors.BOLD}Scan completed{Colors.RESET} at {Colors.CYAN}{datetime.now().strftime("%H:%M:%S")}{Colors.RESET}')
    print(f'{Colors.CYAN}Total hosts discovered: {len(merged)}{Colors.RESET}\n')


if __name__ == "__main__":
    main()