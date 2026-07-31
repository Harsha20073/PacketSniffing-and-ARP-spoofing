from scapy.all import ARP
from colorama import Fore
from datetime import datetime

arp_table = {}
arp_attack_count = 0

def detect_arp_spoof(packet):
    global arp_attack_count

    if packet.haslayer(ARP):

        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc

        if ip in arp_table:

            if arp_table[ip] != mac:

                arp_attack_count += 1

                message = f"""
[{datetime.now()}]
Possible ARP Spoofing Detected
IP Address : {ip}
Old MAC    : {arp_table[ip]}
New MAC    : {mac}
-------------------------------------------------------
"""

                print(Fore.RED + message)

                with open("logs/arp_alerts.log", "a") as f:
                    f.write(message)

        else:
            arp_table[ip] = mac
