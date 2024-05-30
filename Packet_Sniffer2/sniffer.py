from scapy.all import sniff, Raw
from scapy.layers.inet import IP, TCP

def packet_handler(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        print(f"\n[+] New Packet: {ip_layer.src} -> {ip_layer.dst}")
        
        # Check if the packet has a TCP layer
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"TCP Packet: {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}")
            
            # Check if the packet has raw data
            if Raw in packet:
                print(f"Data: {packet[Raw].load}")


print("Starting packet capture...")
sniff(prn=packet_handler, count=10)  # Capture 10 packets
