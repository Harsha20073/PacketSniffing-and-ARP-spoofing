from scapy.all import sniff

def process_packet(packet):
    print(packet.summary())

def start_sniffer():
    print("Sniffing packets... Press Ctrl+C to stop.")
    sniff(prn=process_packet, store=False)
