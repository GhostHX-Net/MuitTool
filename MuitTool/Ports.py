import socket
import ipaddress
import re
import sys
import time
from time import sleep
from threading import Thread, Lock
from queue import Queue


class Colors:
    """ANSI color codes for terminal output."""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    MAGENTA = '\033[95m'
    GRAY = '\033[90m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'


# Common port services mapping
COMMON_PORTS = {
    20: 'FTP Data',
    21: 'FTP Control',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    445: 'SMB',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    8080: 'HTTP Alternate',
    8443: 'HTTPS Alternate',
    9200: 'Elasticsearch',
    27017: 'MongoDB',
    6379: 'Redis',
    5984: 'CouchDB',
    11211: 'Memcached',
}


def clear_screen():
    """Clear terminal screen."""
    import os
    os.system('clear')


def print_header():
    """Display the port scanner header with premium styling."""
    header = f"""
{Colors.BOLD}{Colors.CYAN}
 ╔═══════════════════════════════════════════════════════════════════╗
 ║                                                                   ║
 ║               🔐 ADVANCED PORT SCANNER TOOLKIT 🔐                 ║
 ║                                                                   ║
 ║             Professional Network Service Detection                ║
 ║                     Version 2.0 - Premium                         ║
 ║                                                                   ║
 ╚═══════════════════════════════════════════════════════════════════╝
{Colors.RESET}
"""
    print(header)


def print_banner(text, color=Colors.CYAN):
    """Print a formatted banner."""
    width = 60
    print(f'{color}{"═" * (width + 4)}{Colors.RESET}')
    print(f'{color}║{Colors.RESET}  {text.center(width)}  {color}║{Colors.RESET}')
    print(f'{color}{"═" * (width + 4)}{Colors.RESET}')


def get_service_name(port):
    """Get the service name for a port."""
    return COMMON_PORTS.get(port, 'Unknown Service')


def get_ip_address():
    """Get and validate the target IP address."""
    while True:
        try:
            print(f'{Colors.CYAN}┌─ Target Configuration ─────────────────────────────────┐{Colors.RESET}')
            ip_input = input(f'{Colors.YELLOW}│{Colors.RESET}  {Colors.BOLD}IP Address:{Colors.RESET} ').strip()
            print(f'{Colors.CYAN}└────────────────────────────────────────────────────────┘{Colors.RESET}\n')
            
            ip_address_obj = ipaddress.ip_address(ip_input)
            print(f'{Colors.GREEN}[✓] Valid IP: {Colors.BOLD}{ip_input}{Colors.RESET}\n')
            return str(ip_input)
        except ValueError:
            print(f'{Colors.RED}[✗] Invalid IP address. Please try again.{Colors.RESET}\n')


def get_port_range():
    """Get and validate the port range to scan."""
    port_range_pattern = re.compile(r"([0-9]+)-([0-9]+)")
    
    while True:
        try:
            print(f'{Colors.CYAN}┌─ Port Range Configuration ──────────────────────────────┐{Colors.RESET}')
            print(f'{Colors.CYAN}│{Colors.RESET}  {Colors.DIM}Format: START-END (e.g., 1-1000 or 80,443,3306){Colors.RESET}')
            port_input = input(f'{Colors.CYAN}│{Colors.RESET}  {Colors.BOLD}Port Range:{Colors.RESET} ').strip()
            print(f'{Colors.CYAN}└─────────────────────────────────────────────────────────┘{Colors.RESET}\n')
            
            match = port_range_pattern.search(port_input.replace(" ", ""))
            if match:
                port_min = int(match.group(1))
                port_max = int(match.group(2))
                
                if port_min < 0 or port_max > 65535 or port_min > port_max:
                    print(f'{Colors.RED}[✗] Ports must be 0-65535 and start ≤ end.{Colors.RESET}\n')
                    continue
                
                total_ports = port_max - port_min + 1
                print(f'{Colors.GREEN}[✓] Configured to scan {Colors.BOLD}{total_ports:,}{Colors.GREEN} ports ({port_min}-{port_max}){Colors.RESET}\n')
                return port_min, port_max
            else:
                print(f'{Colors.RED}[✗] Invalid format. Use START-END format (e.g., 1-1000){Colors.RESET}\n')
        except ValueError:
            print(f'{Colors.RED}[✗] Please enter valid port numbers.{Colors.RESET}\n')


def print_progress_bar(current, total):
    """Print a visual progress bar."""
    bar_length = 50
    percent = current / total
    filled = int(bar_length * percent)
    bar = '█' * filled + '░' * (bar_length - filled)
    
    sys.stdout.write(f'\r{Colors.CYAN}[{bar}]{Colors.RESET} {percent*100:6.1f}% ({current:,}/{total:,})')
    sys.stdout.flush()


def scan_port_worker(ip_address, port, results, lock):
    """Worker thread to scan a single port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.15)  # More aggressive timeout for speed
            result = s.connect_ex((ip_address, port))
            
            if result == 0:
                service = get_service_name(port)
                with lock:
                    results.append((port, service))
    except:
        pass


def scan_ports(ip_address, port_min, port_max):
    """Scan ports using multi-threading for speed."""
    open_ports = []
    total_ports = port_max - port_min + 1
    scanned = [0]
    lock = Lock()
    
    print(f'{Colors.BOLD}{Colors.BLUE}[→] Initiating multi-threaded port scan on {Colors.YELLOW}{ip_address}{Colors.BLUE}...{Colors.RESET}\n')
    print(f'{Colors.CYAN}{"─" * 66}{Colors.RESET}\n')
    
    start_time = time.time()
    thread_pool = []
    max_threads = 100  # Adjust for faster/slower scanning
    
    # Create and start threads
    for port in range(port_min, port_max + 1):
        thread = Thread(target=scan_port_worker, args=(ip_address, port, open_ports, lock))
        thread.daemon = True
        thread_pool.append(thread)
        thread.start()
        
        # Keep thread pool size manageable
        if len([t for t in thread_pool if t.is_alive()]) >= max_threads:
            while len([t for t in thread_pool if t.is_alive()]) >= max_threads:
                time.sleep(0.01)
        
        # Update progress
        with lock:
            scanned[0] += 1
            if scanned[0] % max(1, total_ports // 50) == 0:  # Update less frequently
                print_progress_bar(scanned[0], total_ports)
    
    # Wait for all threads to complete
    for thread in thread_pool:
        thread.join()
    
    elapsed_time = time.time() - start_time
    print(f'\n\n{Colors.CYAN}{"─" * 66}{Colors.RESET}\n')
    
    return open_ports, elapsed_time


def display_results(ip_address, open_ports, elapsed_time):
    """Display scan results with professional formatting."""
    print(f'{Colors.BOLD}{Colors.CYAN}[✓] SCAN COMPLETE!{Colors.RESET}\n')
    
    # Calculate scanning statistics
    speed = len(open_ports) / elapsed_time if elapsed_time > 0 else 0
    
    print(f'{Colors.MAGENTA}┌─ SCAN SUMMARY ──────────────────────────────────────────┐{Colors.RESET}')
    print(f'{Colors.MAGENTA}│{Colors.RESET}  {Colors.BOLD}Target IP:{Colors.RESET}      {Colors.YELLOW}{ip_address}{Colors.RESET}')
    print(f'{Colors.MAGENTA}│{Colors.RESET}  {Colors.BOLD}Scan Time:{Colors.RESET}      {Colors.YELLOW}{elapsed_time:.2f}s{Colors.RESET}')
    print(f'{Colors.MAGENTA}│{Colors.RESET}  {Colors.BOLD}Open Ports:{Colors.RESET}     {Colors.GREEN}{len(open_ports)}{Colors.RESET}')
    print(f'{Colors.MAGENTA}│{Colors.RESET}  {Colors.BOLD}Scan Speed:{Colors.RESET}     {Colors.YELLOW}{speed:.0f} ports/sec{Colors.RESET}')
    print(f'{Colors.MAGENTA}└─────────────────────────────────────────────────────────┘{Colors.RESET}\n')
    
    if open_ports:
        print(f'{Colors.BOLD}{Colors.GREEN}═══ OPEN PORTS & SERVICES ═══{Colors.RESET}\n')
        
        for port, service in sorted(open_ports):
            risk_level = get_risk_level(port)
            risk_color = get_risk_color(risk_level)
            
            print(f'  {Colors.GREEN}●{Colors.RESET}  {Colors.BOLD}Port {port:5d}{Colors.RESET}  {Colors.GRAY}|{Colors.RESET}  {Colors.CYAN}{service:<20}{Colors.RESET}  {Colors.GRAY}|{Colors.RESET}  {risk_color}[{risk_level.upper()}]{Colors.RESET}')
        
        print(f'\n{Colors.BOLD}{Colors.GREEN}═════════════════════════════{Colors.RESET}\n')
    else:
        print(f'{Colors.YELLOW}[!] No open ports detected in the specified range.{Colors.RESET}\n')


def get_risk_level(port):
    """Determine security risk level for a port."""
    high_risk = [21, 23, 445, 3389, 3306, 27017]
    medium_risk = [22, 25, 53, 110, 143, 5900]
    
    if port in high_risk:
        return 'HIGH'
    elif port in medium_risk:
        return 'MEDIUM'
    else:
        return 'LOW'


def get_risk_color(risk_level):
    """Get color for risk level."""
    if risk_level == 'HIGH':
        return Colors.RED
    elif risk_level == 'MEDIUM':
        return Colors.YELLOW
    else:
        return Colors.GREEN


def main():
    """Main application flow."""
    try:
        clear_screen()
        print_header()
        
        # Get user inputs
        target_ip = get_ip_address()
        port_min, port_max = get_port_range()
        
        # Perform scan
        open_ports, elapsed_time = scan_ports(target_ip, port_min, port_max)
        
        # Display results
        display_results(target_ip, open_ports, elapsed_time)
        
        input(f'{Colors.DIM}Press Enter to return to menu...{Colors.RESET}')
        
    except KeyboardInterrupt:
        print(f'\n\n{Colors.RED}[✗] Scan interrupted by user.{Colors.RESET}\n')
        sys.exit(0)
    except Exception as e:
        print(f'{Colors.RED}[✗] An error occurred: {e}{Colors.RESET}')
        sys.exit(1)


if __name__ == '__main__':
    main()