import socket, os
s = socket.gethostname()
class Colors:
    """ANSI escape codes for colors and styles."""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m' # Resets all styles to default
Ac = r'''
 _____ ______   ___  ___  ___  _________  _________  ________  ________  ___          
|\   _ \  _   \|\  \|\  \|\  \|\___   ___\\___   ___\\   __  \|\   __  \|\  \         
\ \  \\\__\ \  \ \  \\\  \ \  \|___ \  \_\|___ \  \_\ \  \|\  \ \  \|\  \ \  \        
 \ \  \\|__| \  \ \  \\\  \ \  \   \ \  \     \ \  \ \ \  \\\  \ \  \\\  \ \  \       
  \ \  \    \ \  \ \  \\\  \ \  \   \ \  \     \ \  \ \ \  \\\  \ \  \\\  \ \  \____  
   \ \__\    \ \__\ \_______\ \__\   \ \__\     \ \__\ \ \_______\ \_______\ \_______\
    \|__|     \|__|\|_______|\|__|    \|__|      \|__|  \|_______|\|_______|\|_______|
'''
name = Colors.RED + 'By GhostHX' + Colors.RESET
os.system('clear')
while True:
    print(f'{Colors.CYAN}{Ac}{Colors.RESET}                                                                              {name}')
    print('-' * 88)
    print("1:[+]Port scanner>")
    print("2:[+]Wifi DDoS attacker>")
    print("3:[+]IP address getter>")
    print("4:[+]Sniff>")
    user_input = input("># ")
    if user_input == "1":
        os.system("sudo python Ports.py")
    elif user_input == "2":
        os.system("sudo python DDoS.py")
    elif user_input == "3":
        os.system("sudo python scan.py")
    elif user_input == "4":
        os.system("sudo python Sniff.py")