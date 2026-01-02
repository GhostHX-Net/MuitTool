import socket
import os
import sys
import time
import threading
from Passsword import *


class Colors:
    """ANSI escape codes for colors and styles."""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    DIM = '\033[2m'
    RESET = '\033[0m'
    BG_DARK = '\033[40m'
    BG_BLUE = '\033[44m'


BANNER = r'''
 ╔══════════════════════════════════════════════════════════════════════════╗
 ║                                                                          ║
 ║     ███╗   ███╗██╗   ██╗██╗████████╗████████╗ ██████╗  ██████╗ ██╗       ║
 ║     ████╗ ████║██║   ██║██║╚══██╔══╝╚══██╔══╝██╔═══██╗██╔═══██╗██║       ║
 ║     ██╔████╔██║██║   ██║██║   ██║      ██║   ██║   ██║██║   ██║██║       ║
 ║     ██║╚██╔╝██║██║   ██║██║   ██║      ██║   ██║   ██║██║   ██║██║       ║
 ║     ██║ ╚═╝ ██║╚██████╔╝██║   ██║      ██║   ╚██████╔╝╚██████╔╝███████╗  ║
 ║     ╚═╝     ╚═╝ ╚═════╝ ╚═╝   ╚═╝      ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝  ║
 ║                                                                          ║
 ║            🔓 ADVANCED NETWORK SECURITY TOOLKIT 🔓                       ║
 ║                   Version 2.0 - Professional Edition                     ║
 ║                         Author: GhostHX                                  ║
 ║                                                                          ║
 ╚══════════════════════════════════════════════════════════════════════════╝
'''

MENU_ITEMS = [
    ("1", "Port Scanner", "🔍 Scan network ports for open services", "Ports.py"),
    ("2", "WiFi DDoS Attacker", "💥 Launch distributed denial attacks", "DDoS.py"),
    ("3", "IP Address Getter", "📍 Retrieve and track IP addresses", "scan.py"),
    ("4", "Packet Sniffer", "📡 Capture and analyze network traffic", "Sniff.py"),
    ("5", "Password Manager", "🔐 Secure password storage & management", None),
    ("6", "Exit", "❌ Close the application", None),
]


def clear_screen():
    """Clear the terminal screen."""
    os.system('clear')


def print_box(text, color=Colors.CYAN, width=76):
    """Print text in a nice box."""
    print(f'{color}╔{"═" * width}╗{Colors.RESET}')
    print(f'{color}║{Colors.RESET} {text.center(width - 1)}{color}║{Colors.RESET}')
    print(f'{color}╚{"═" * width}╝{Colors.RESET}')


def loading_animation(duration=1):
    """Show a loading animation."""
    frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
    end_time = time.time() + duration
    while time.time() < end_time:
        for frame in frames:
            sys.stdout.write(f'\r{Colors.YELLOW}{frame} Loading...{Colors.RESET}')
            sys.stdout.flush()
            time.sleep(0.1)
    sys.stdout.write('\r' + ' ' * 30 + '\r')
    sys.stdout.flush()


def display_banner():
    """Display the application banner with enhanced styling."""
    print(f'{Colors.BOLD}{Colors.CYAN}{BANNER}{Colors.RESET}')
    print()


def display_menu(hostname):
    """Display the main menu with enhanced formatting and categories."""
    print(f'{Colors.BOLD}{Colors.GREEN}┌─ RECONNAISSANCE & SCANNING ────────────────────────────────────┐{Colors.RESET}')
    print(f'{Colors.GREEN}│{Colors.RESET}  {Colors.BOLD}1.{Colors.RESET} Port Scanner           {Colors.DIM}Scan network ports for services{Colors.RESET}{Colors.GREEN}     |{Colors.RESET}')
    print(f'{Colors.GREEN}│{Colors.RESET}  {Colors.BOLD}3.{Colors.RESET} IP Address Getter     {Colors.DIM}Retrieve and track IPs{Colors.RESET}{Colors.GREEN}               |{Colors.RESET}')
    print(f'{Colors.GREEN}│{Colors.RESET}  {Colors.BOLD}4.{Colors.RESET} Packet Sniffer        {Colors.DIM}Analyze network traffic{Colors.RESET}{Colors.GREEN}              |{Colors.RESET}')
    print(f'{Colors.GREEN}|{Colors.RESET}  {Colors.BOLD}6.{Colors.RESET} AV Port scanner       {Colors.DIM}AV port scanner the best{Colors.RESET}{Colors.GREEN}             |{Colors.RESET}')
    print(f'{Colors.GREEN}└────────────────────────────────────────────────────────────────┘{Colors.RESET}')
    
    print()
    print(f'{Colors.BOLD}{Colors.RED}┌─ ATTACK & EXPLOIT ─────────────────────────────────────────────┐{Colors.RESET}')
    print(f'{Colors.RED}│{Colors.RESET}  {Colors.BOLD}2.{Colors.RESET} WiFi DDoS Attacker    {Colors.DIM}Launch distributed denial{Colors.RESET}{Colors.RED}            |{Colors.RESET}')
    print(f'{Colors.RED}└────────────────────────────────────────────────────────────────┘{Colors.RESET}')
    
    print()
    print(f'{Colors.BOLD}{Colors.MAGENTA}┌─ SECURITY UTILITIES ───────────────────────────────────────────┐{Colors.RESET}')
    print(f'{Colors.MAGENTA}│{Colors.RESET}  {Colors.BOLD}5.{Colors.RESET} Password Manager      {Colors.DIM}Secure password storage{Colors.RESET}{Colors.MAGENTA}              |{Colors.RESET}')
    print(f'{Colors.MAGENTA}└────────────────────────────────────────────────────────────────┘{Colors.RESET}')
    
    print()
    print(f'{Colors.BOLD}{Colors.YELLOW}┌─ SYSTEM ───────────────────────────────────────────────────────┐{Colors.RESET}')
    print(f'{Colors.YELLOW}│{Colors.RESET}  {Colors.BOLD}7.{Colors.RESET} Exit                  {Colors.DIM}Close the application{Colors.RESET}{Colors.YELLOW}                |{Colors.RESET}')
    print(f'{Colors.YELLOW}└────────────────────────────────────────────────────────────────┘{Colors.RESET}')
    print()


def get_user_choice(hostname):
    """Get user input with styled prompt."""
    try:
        choice = input(f'{Colors.BOLD}{Colors.CYAN}┌─ {hostname.upper()}@muitool {Colors.RESET}{Colors.BOLD}{Colors.CYAN}─┐{Colors.RESET}\n{Colors.CYAN}└─→{Colors.RESET} {Colors.BOLD}').strip()
        sys.stdout.write(Colors.RESET)
        return choice
    except KeyboardInterrupt:
        print(f'\n\n{Colors.RED}[✗] Interrupted by user{Colors.RESET}')
        sys.exit(0)


def execute_option(choice):
    """Execute the selected option with enhanced feedback."""
    valid_options = {opt[0]: (opt[1], opt[3]) for opt in MENU_ITEMS}
    
    if choice not in valid_options:
        print(f'{Colors.RED}[✗] Invalid option "{choice}". Please select 1-6.{Colors.RESET}')
        time.sleep(1.5)
        return False
    
    option_name, script = valid_options[choice]
    
    if choice == "7":  # Exit
        print_box(f"Exiting MuitTool v2.0 - Goodbye! 👋", Colors.YELLOW)
        print()
        sys.exit(0)
    elif choice == "5":  # Password Manager
        print(f'{Colors.BLUE}[→] Launching Password Manager...{Colors.RESET}\n')
        loading_animation(0.5)
        Pwd()
        time.sleep(1)
    elif choice == '4':
        print(f'{Colors.BLUE}[→] Launching Packet Sniffer...{Colors.RESET}\n')
        loading_animation(0.5)
        os.system("sudo python Sniff.py")
    elif choice == '3':
        print(f'{Colors.BLUE}[→] Launching IP Getter...{Colors.RESET}\n')
        loading_animation(0.5)
        os.system("sudo python scan.py")
    elif choice == '2':
        print(f'{Colors.BLUE}[→] Launching WiFi DDoS...{Colors.RESET}\n')
        loading_animation(0.5)
        os.system("sudo python DDoS.py")
    elif choice == '1':
        print(f'{Colors.BLUE}[→] Launching Port Scanner...{Colors.RESET}\n')
        loading_animation(0.5)
        os.system("sudo python Ports.py")
    elif choice == '6':
        print(f'{Colors.BLUE}[→] Launching AV_Port Scanner...{Colors.RESET}\n')
        loading_animation(0.5)
        os.system("sudo python AV_port.py")
    elif script:  # External script
        try:
            print(f'\n{Colors.BLUE}[→] Launching {option_name}...{Colors.RESET}\n')
            loading_animation(0.8)
            os.system(f"sudo python {script}")
            time.sleep(1)
            print(f'\n{Colors.BLUE}[→] Returning to main menu...{Colors.RESET}')
            time.sleep(1)
        except Exception as e:
            print(f'{Colors.RED}[✗] Error executing {script}: {e}{Colors.RESET}')
        return True
    
    return False


def display_system_info(hostname):
    """Display current system info at the top."""
    try:
        user = os.getenv('USER', 'root')
        print(f'{Colors.DIM}{Colors.GRAY}╭─ System: {user}@{hostname} | MuitTool v2.0 ─╮{Colors.RESET}')
    except:
        pass


def main():
    """Main application loop with enhanced UX."""
    hostname = socket.gethostname()
    
    try:
        while True:
            clear_screen()
            display_banner()
            display_system_info(hostname)
            print()
            display_menu(hostname)
            choice = get_user_choice(hostname)
            
            if choice:
                execute_option(choice)
            
            if choice not in ["6"]:
                input(f'\n{Colors.DIM}[Press Enter to continue...]{Colors.RESET}')
    
    except KeyboardInterrupt:
        print(f'\n\n{Colors.RED}[✗] Program interrupted by user{Colors.RESET}\n')
        sys.exit(0)
    except Exception as e:
        print(f'{Colors.RED}[✗] Unexpected error: {e}{Colors.RESET}')
        time.sleep(1)
        sys.exit(1)


if __name__ == '__main__':
    main()
