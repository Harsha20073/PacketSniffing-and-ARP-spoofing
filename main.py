from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Ether
from scapy.layers.dns import DNS, DNSQR
from arp_detector import detect_arp_spoof
from interface import choose_interface
from colorama import init, Fore
from datetime import datetime
import argparse
import csv
import os


init(autoreset=True)


# ==========================
# COMMAND LINE ARGUMENTS
# ==========================

parser = argparse.ArgumentParser(
    description="NetSentinel Packet Sniffer"
)

parser.add_argument(
    "-i",
    "--interface",
    help="Network interface"
)

args = parser.parse_args()



# ==========================
# STATISTICS
# ==========================

stats = {
    "Total": 0,
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0,
    "ARP": 0
}


CSV_FILE = "packet_log.csv"



# ==========================
# CREATE CSV FILE
# ==========================

if not os.path.exists(CSV_FILE):

    with open(CSV_FILE, "w", newline="") as file:

        writer = csv.writer(file)

        writer.writerow([
            "Time",
            "Protocol",
            "Source IP",
            "Destination IP",
            "Source MAC",
            "Destination MAC",
            "Source Port",
            "Destination Port",
            "Size"
        ])




# ==========================
# REPORT GENERATOR
# ==========================

def generate_report():

    with open("session_report.txt", "w") as file:

        file.write("====================\n")
        file.write(" NetSentinel Report\n")
        file.write("====================\n\n")

        for key, value in stats.items():

            file.write(
                f"{key}: {value}\n"
            )





# ==========================
# CSV LOGGER
# ==========================

def save_csv(data):

    with open(CSV_FILE, "a", newline="") as file:

        writer = csv.writer(file)

        writer.writerow(data)




# ==========================
# PACKET ANALYSIS
# ==========================

def packet_callback(packet):

    stats["Total"] += 1


    detect_arp_spoof(packet)


    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


    if packet.haslayer(IP):

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst


        src_mac = "-"
        dst_mac = "-"


        if packet.haslayer(Ether):

            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst



        protocol = "IP"

        src_port = "-"
        dst_port = "-"



        # TCP

        if packet.haslayer(TCP):

            stats["TCP"] += 1

            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport


            if src_port == 443 or dst_port == 443:

                protocol = "HTTPS"

            elif src_port == 80 or dst_port == 80:

                protocol = "HTTP"

            else:

                protocol = "TCP"



        # UDP

        elif packet.haslayer(UDP):

            stats["UDP"] += 1

            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport


            if packet.haslayer(DNS):

                protocol = "DNS"

            else:

                protocol = "UDP"



        # ICMP

        elif packet.haslayer(ICMP):

            stats["ICMP"] += 1

            protocol = "ICMP"



        print(
            Fore.CYAN +
            "\n" + "=" * 60
        )

        print(
            Fore.GREEN +
            f"Packet #{stats['Total']}"
        )

        print(
            f"Time : {timestamp}"
        )

        print(
            Fore.YELLOW +
            f"Protocol : {protocol}"
        )

        print(
            f"Source IP : {src_ip}"
        )

        print(
            f"Destination IP : {dst_ip}"
        )

        print(
            f"Source MAC : {src_mac}"
        )

        print(
            f"Destination MAC : {dst_mac}"
        )

        print(
            f"Source Port : {src_port}"
        )

        print(
            f"Destination Port : {dst_port}"
        )

        print(
            f"Size : {len(packet)} bytes"
        )



        if packet.haslayer(DNSQR):

            try:

                domain = packet[DNSQR].qname.decode()

                print(
                    Fore.MAGENTA +
                    f"DNS Query : {domain}"
                )

            except:

                pass



        print(
            Fore.CYAN +
            "=" * 60
        )



        save_csv([
            timestamp,
            protocol,
            src_ip,
            dst_ip,
            src_mac,
            dst_mac,
            src_port,
            dst_port,
            len(packet)
        ])




    elif packet.haslayer(ARP):

        stats["ARP"] += 1


        print(
            Fore.YELLOW +
            "\nARP Packet"
        )

        print(
            f"Source IP : {packet[ARP].psrc}"
        )

        print(
            f"Source MAC : {packet[ARP].hwsrc}"
        )





# ==========================
# MAIN PROGRAM
# ==========================

print(
    Fore.CYAN +
    "=" * 60
)

print(
    Fore.GREEN +
    "        NetSentinel"
)

print(
    Fore.GREEN +
    " Packet Sniffer + ARP Detector"
)

print(
    Fore.CYAN +
    "=" * 60
)



try:


    # Interface selection

    if args.interface:

        interface = args.interface

    else:

        interface = choose_interface()



    print(
        Fore.GREEN +
        f"\nListening on : {interface}"
    )



    print("\nProtocol Filter")

    print("1. All")

    print("2. TCP")

    print("3. UDP")

    print("4. ICMP")

    print("5. ARP")


    choice = input(
        "Select option : "
    )


    capture_filter = None


    if choice == "2":

        capture_filter = "tcp"


    elif choice == "3":

        capture_filter = "udp"


    elif choice == "4":

        capture_filter = "icmp"


    elif choice == "5":

        capture_filter = "arp"



    print(
        Fore.GREEN +
        "\nSniffing started..."
    )

    print(
        "Press Ctrl+C to stop"
    )


    sniff(
        iface=interface,
        filter=capture_filter,
        prn=packet_callback,
        store=False
    )



except KeyboardInterrupt:


    print(
        Fore.RED +
        "\nStopping NetSentinel..."
    )



finally:


    generate_report()


    print(
        "\n" + "=" * 60
    )

    print(
        Fore.GREEN +
        "SESSION SUMMARY"
    )

    print(
        "=" * 60
    )


    for key,value in stats.items():

        print(
            f"{key}: {value}"
        )


    print(
        "=" * 60
    )

    print(
        "Report saved: session_report.txt"
    )

    print(
        "CSV saved: packet_log.csv"
    )
