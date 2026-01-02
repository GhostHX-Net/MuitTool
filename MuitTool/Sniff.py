#!/usr/bin/env python3
"""
Advanced DNS Packet Sniffer Tool
Captures, analyzes, and logs DNS traffic with comprehensive statistics.
"""
import sys
import os
import signal
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from typing import Optional, Tuple

try:
    from scapy.all import sniff, wrpcap, Ether, IP, TCP, UDP, conf
    from scapy.layers.dns import DNS, DNSQR, DNSRR
except ImportError:
    print("Error: Scapy library not found. Install with: pip install scapy")
    sys.exit(1)


class Colors:
    """ANSI color codes for terminal output with better contrast."""
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


class DNSPacketSniffer:
    """Advanced DNS packet sniffer with comprehensive traffic analysis."""
    
    def __init__(self, interface: Optional[str] = None, pcap_file: Optional[str] = None):
        """Initialize the sniffer with optional interface and output file."""
        self.interface = interface
        self.pcap_file = pcap_file
        self.packet_count = 0
        self.dns_queries = defaultdict(int)
        self.dns_responses = defaultdict(int)
        self.source_ips = defaultdict(int)
        self.destination_ips = defaultdict(int)
        self.protocols = defaultdict(int)
        self.capture_start_time = datetime.now()
        
    @staticmethod
    def clear_screen() -> None:
        """Clear terminal screen safely."""
        os.system('clear' if os.name != 'nt' else 'cls')

    def print_header(self) -> None:
        """Display an attractive sniffer header with status information."""
        header = f"""{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║           🔍  ADVANCED DNS PACKET SNIFFER TOOL  🔍           ║
║                                                              ║
║                DNS Traffic Analysis & Monitoring             ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
{Colors.RESET}"""
        print(header)
        print(f'{Colors.YELLOW}⏱  {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{Colors.RESET}')
        print(f'{Colors.GREEN}✓ Starting packet capture...{Colors.RESET}')
        print(f'{Colors.YELLOW}⚠  Press Ctrl+C to stop and view summary{Colors.RESET}\n')
        print(f'{Colors.DIM}{"─" * 70}{Colors.RESET}\n')

    def extract_dns_info(self, packet) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Extract DNS information from packet.
        Returns tuple of (query_name, response_ip, dns_type)
        """
        try:
            if DNS not in packet:
                return None, None, None
                
            # DNS Query
            if packet[DNS].qr == 0 and packet.haslayer(DNSQR):
                query_name = packet[DNSQR].qname.decode(errors="ignore").rstrip('.')
                return query_name, None, "QUERY"
            
            # DNS Response
            elif packet[DNS].qr == 1 and packet.haslayer(DNSRR):
                query_name = None
                response_ip = None
                
                if packet.haslayer(DNSQR):
                    query_name = packet[DNSQR].qname.decode(errors="ignore").rstrip('.')
                if packet.haslayer(DNSRR):
                    try:
                        response_ip = str(packet[DNSRR].rdata)
                    except (AttributeError, TypeError):
                        response_ip = None
                        
                return query_name, response_ip, "RESPONSE"
                
        except (AttributeError, IndexError, UnicodeDecodeError):
            pass
        
        return None, None, None

    def process_packet(self, packet) -> None:
        """Process and analyze each captured packet."""
        self.packet_count += 1
        
        try:
            # Extract layer 3 information
            src_ip = packet[IP].src if IP in packet else "N/A"
            dst_ip = packet[IP].dst if IP in packet else "N/A"
            src_mac = packet[Ether].src if packet.haslayer(Ether) else "N/A"
            dst_mac = packet[Ether].dst if packet.haslayer(Ether) else "N/A"
            
            # Determine protocol
            if packet.haslayer(TCP):
                protocol = "TCP"
            elif packet.haslayer(UDP):
                protocol = "UDP"
            else:
                protocol = "Other"
            
            # Update statistics
            self.source_ips[src_ip] += 1
            self.destination_ips[dst_ip] += 1
            self.protocols[protocol] += 1
            
            # Extract DNS information
            query_name, response_ip, dns_type = self.extract_dns_info(packet)
            
            if query_name and dns_type:
                if dns_type == "QUERY":
                    self.dns_queries[query_name] += 1
                    self.print_dns_packet(src_ip, dst_ip, src_mac, dst_mac, query_name, None, dns_type)
                elif dns_type == "RESPONSE":
                    self.dns_responses[query_name] += 1
                    self.print_dns_packet(src_ip, dst_ip, src_mac, dst_mac, query_name, response_ip, dns_type)
            
            # Save to pcap if requested
            if self.pcap_file:
                try:
                    wrpcap(self.pcap_file, packet, append=True)
                except (OSError, IOError) as e:
                    pass
                    
        except Exception:
            pass

    def print_dns_packet(self, src_ip: str, dst_ip: str, src_mac: str, dst_mac: str, 
                        domain: str, response_ip: Optional[str] = None, dns_type: str = "QUERY") -> None:
        """Print formatted and colorized DNS packet information."""
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        if dns_type == "QUERY":
            color = Colors.CYAN
            icon = "📤"
            prefix = f"{Colors.BLUE}>>>{Colors.RESET}"
        else:
            color = Colors.GREEN
            icon = "📥"
            prefix = f"{Colors.GREEN}<<<{Colors.RESET}"
        
        print(f'{prefix} [{timestamp}] {color}{Colors.BOLD}{dns_type}{Colors.RESET}')
        print(f'    {Colors.BOLD}Domain:{Colors.RESET} {Colors.YELLOW}{domain}{Colors.RESET}')
        print(f'    {Colors.BOLD}Source:{Colors.RESET} {Colors.CYAN}{src_ip}{Colors.RESET} ({Colors.DIM}{src_mac}{Colors.RESET})')
        print(f'    {Colors.BOLD}Destination:{Colors.RESET} {Colors.CYAN}{dst_ip}{Colors.RESET} ({Colors.DIM}{dst_mac}{Colors.RESET})')
        
        if response_ip:
            print(f'    {Colors.BOLD}{Colors.GREEN}Response:{Colors.RESET} {Colors.MAGENTA}{response_ip}{Colors.RESET}')
        
        print(f'{Colors.DIM}{"─" * 70}{Colors.RESET}')

    def print_summary(self) -> None:
        """Print comprehensive capture summary with statistics."""
        elapsed_time = (datetime.now() - self.capture_start_time).total_seconds()
        pps = self.packet_count / elapsed_time if elapsed_time > 0 else 0
        
        header = f"""{Colors.BOLD}{Colors.CYAN}
╔══════════════════════════════════════════════════════════════╗
║                    CAPTURE SUMMARY REPORT                   ║
╚══════════════════════════════════════════════════════════════╝
{Colors.RESET}"""
        print(header)
        
        # Packet Statistics
        print(f'\n{Colors.BOLD}{Colors.YELLOW}📊 Packet Statistics:{Colors.RESET}')
        print(f'   {Colors.GREEN}Total Packets:{Colors.RESET} {Colors.CYAN}{self.packet_count}{Colors.RESET}')
        print(f'   {Colors.GREEN}DNS Queries:{Colors.RESET} {Colors.CYAN}{len(self.dns_queries)}{Colors.RESET}')
        print(f'   {Colors.GREEN}DNS Responses:{Colors.RESET} {Colors.CYAN}{len(self.dns_responses)}{Colors.RESET}')
        print(f'   {Colors.GREEN}Capture Duration:{Colors.RESET} {Colors.CYAN}{elapsed_time:.2f}s{Colors.RESET}')
        print(f'   {Colors.GREEN}Packets/Second:{Colors.RESET} {Colors.CYAN}{pps:.2f}{Colors.RESET}')
        
        # Top Queried Domains
        print(f'\n{Colors.BOLD}{Colors.YELLOW}🔗 Top Queried Domains:{Colors.RESET}')
        if self.dns_queries:
            sorted_queries = sorted(self.dns_queries.items(), key=lambda x: x[1], reverse=True)
            for idx, (domain, count) in enumerate(sorted_queries[:10], 1):
                bar = "█" * min(count // max(1, max([c for _, c in sorted_queries[:10]]) // 20), 20)
                print(f'   {Colors.DIM}{idx:2d}.{Colors.RESET} {Colors.CYAN}{domain:<45}{Colors.RESET} {Colors.GREEN}{bar}{Colors.RESET} {count}')
        else:
            print(f'   {Colors.DIM}No DNS queries captured{Colors.RESET}')
        
        # Top Source IPs
        print(f'\n{Colors.BOLD}{Colors.YELLOW}📡 Top Source IPs:{Colors.RESET}')
        if self.source_ips:
            sorted_src = sorted(self.source_ips.items(), key=lambda x: x[1], reverse=True)
            for idx, (ip, count) in enumerate(sorted_src[:5], 1):
                bar = "█" * min(count // max(1, max([c for _, c in sorted_src[:5]]) // 20), 20)
                print(f'   {Colors.DIM}{idx}. {Colors.RESET}{Colors.BLUE}{ip:<20}{Colors.RESET} {Colors.GREEN}{bar}{Colors.RESET} {count}')
        else:
            print(f'   {Colors.DIM}No source IPs captured{Colors.RESET}')
        
        # Top Destination IPs
        print(f'\n{Colors.BOLD}{Colors.YELLOW}📍 Top Destination IPs:{Colors.RESET}')
        if self.destination_ips:
            sorted_dst = sorted(self.destination_ips.items(), key=lambda x: x[1], reverse=True)
            for idx, (ip, count) in enumerate(sorted_dst[:5], 1):
                bar = "█" * min(count // max(1, max([c for _, c in sorted_dst[:5]]) // 20), 20)
                print(f'   {Colors.DIM}{idx}. {Colors.RESET}{Colors.BLUE}{ip:<20}{Colors.RESET} {Colors.GREEN}{bar}{Colors.RESET} {count}')
        else:
            print(f'   {Colors.DIM}No destination IPs captured{Colors.RESET}')
        
        # Protocol Distribution
        print(f'\n{Colors.BOLD}{Colors.YELLOW}🔌 Protocol Distribution:{Colors.RESET}')
        if self.protocols:
            for protocol, count in sorted(self.protocols.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / self.packet_count * 100) if self.packet_count > 0 else 0
                bar = "█" * int(percentage // 5)
                print(f'   {Colors.MAGENTA}{protocol:<10}{Colors.RESET} {Colors.GREEN}{bar}{Colors.RESET} {count:5d} ({percentage:5.1f}%)')
        
        # Save status
        if self.pcap_file:
            print(f'\n{Colors.GREEN}[✓] Packets saved to: {self.pcap_file}{Colors.RESET}')
        
        print(f'\n{Colors.DIM}{"─" * 70}{Colors.RESET}\n')

    def start_sniffing(self) -> None:
        """Start packet capture with DNS filter."""
        dns_filter = "udp port 53 or tcp port 53"
        
        try:
            print(f'{Colors.BLUE}[*] DNS Filter: {Colors.YELLOW}{dns_filter}{Colors.RESET}')
            
            if self.interface:
                print(f'{Colors.BLUE}[*] Interface: {Colors.YELLOW}{self.interface}{Colors.RESET}\n')
            else:
                print(f'{Colors.BLUE}[*] Interface: {Colors.YELLOW}Default{Colors.RESET}\n')
            
            sniff_kwargs = {
                'filter': dns_filter,
                'prn': self.process_packet,
                'store': False,
            }
            
            if self.interface:
                sniff_kwargs['iface'] = self.interface
            
            sniff(**sniff_kwargs)
            
        except PermissionError:
            print(f'\n{Colors.RED}[✗] Permission denied. This tool requires root/administrator privileges.{Colors.RESET}')
            print(f'{Colors.YELLOW}[*] Run with: sudo python3 {sys.argv[0]}{Colors.RESET}')
            sys.exit(1)
        except OSError as e:
            if "No such device" in str(e):
                print(f'\n{Colors.RED}[✗] Interface not found: {self.interface}{Colors.RESET}')
            else:
                print(f'\n{Colors.RED}[✗] Network error: {e}{Colors.RESET}')
            sys.exit(1)
        except Exception as e:
            print(f'\n{Colors.RED}[✗] Unexpected error: {e}{Colors.RESET}')
            sys.exit(1)


def get_interface() -> Optional[str]:
    """
    Prompt user to select or specify network interface.
    Returns interface name or None for default.
    """
    print(f'{Colors.YELLOW}╔════════════════════════════════════════════════════════════╗{Colors.RESET}')
    print(f'{Colors.BOLD}{Colors.YELLOW}[?] Select Network Interface{Colors.RESET}')
    print(f'{Colors.YELLOW}╚════════════════════════════════════════════════════════════╝{Colors.RESET}')
    print(f'{Colors.DIM}Common interfaces: eth0, wlan0, en0, tun0{Colors.RESET}')
    print(f'{Colors.DIM}Leave blank to use default interface{Colors.RESET}\n')
    
    interface = input(f'{Colors.BOLD}{Colors.CYAN}► Interface > {Colors.RESET}').strip()
    return interface if interface else None


def get_pcap_file() -> Optional[str]:
    """
    Prompt user for PCAP output file path.
    Returns file path or None to skip saving.
    """
    print(f'\n{Colors.YELLOW}╔════════════════════════════════════════════════════════════╗{Colors.RESET}')
    print(f'{Colors.BOLD}{Colors.YELLOW}[?] Save Packets to PCAP File{Colors.RESET}')
    print(f'{Colors.YELLOW}╚════════════════════════════════════════════════════════════╝{Colors.RESET}')
    print(f'{Colors.DIM}Example: ./capture.pcap, packets.pcap{Colors.RESET}')
    print(f'{Colors.DIM}Leave blank to skip saving{Colors.RESET}\n')
    
    pcap = input(f'{Colors.BOLD}{Colors.CYAN}► File path > {Colors.RESET}').strip()
    return pcap if pcap else None


def signal_handler(signum, frame) -> None:
    """Handle SIGINT (Ctrl+C) gracefully."""
    print(f'\n{Colors.YELLOW}[*] Capture interrupted by user.{Colors.RESET}')
    sys.exit(0)


def main() -> None:
    """Main application entry point and control flow."""
    try:
        # Clear screen for fresh start
        DNSPacketSniffer.clear_screen()
        
        # Initialize sniffer
        sniffer = DNSPacketSniffer()
        sniffer.print_header()
        
        # Register signal handler for graceful shutdown
        signal.signal(signal.SIGINT, signal_handler)
        
        # Get user configuration
        interface = get_interface()
        if interface:
            sniffer.interface = interface
            print(f'{Colors.GREEN}✓ Using interface: {Colors.CYAN}{interface}{Colors.RESET}\n')
        
        pcap_file = get_pcap_file()
        if pcap_file:
            # Validate pcap file path
            try:
                Path(pcap_file).parent.mkdir(parents=True, exist_ok=True)
                sniffer.pcap_file = pcap_file
                print(f'{Colors.GREEN}✓ Packets will be saved to: {Colors.CYAN}{pcap_file}{Colors.RESET}\n')
            except OSError as e:
                print(f'{Colors.YELLOW}[!] Warning: Cannot write to {pcap_file}: {e}{Colors.RESET}')
                print(f'{Colors.YELLOW}[*] Continuing without PCAP output...{Colors.RESET}\n')
        
        # Start the sniffer
        sniffer.start_sniffing()
        
    except KeyboardInterrupt:
        print(f'\n{Colors.YELLOW}[*] Capture stopped by user.{Colors.RESET}')
        if 'sniffer' in locals():
            sniffer.print_summary()
    except Exception as e:
        print(f'{Colors.RED}[✗] Fatal error: {e}{Colors.RESET}')
        sys.exit(1)


if __name__ == "__main__":
    main()