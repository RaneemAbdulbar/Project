import threading
import tkinter as tk
from tkinter import scrolledtext, ttk
from scapy.all import sniff, get_if_list
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
import pyshark

# Global variable to control the sniffing threads
running = False

# Define a packet handler function for scapy
def packet_handler(packet):
    if Ether in packet:
        ether_layer = packet[Ether]
        log_packet(f"Ethernet Frame: {ether_layer.src} -> {ether_layer.dst}")

    if IP in packet:
        ip_layer = packet[IP]
        log_packet(f"IP Packet: {ip_layer.src} -> {ip_layer.dst}")

    if TCP in packet:
        tcp_layer = packet[TCP]
        log_packet(f"TCP Segment: {tcp_layer.sport} -> {tcp_layer.dport}")

    if UDP in packet:
        udp_layer = packet[UDP]
        log_packet(f"UDP Datagram: {udp_layer.sport} -> {udp_layer.dport}")

# Define a function to analyze packets with pyshark
def analyze_packets(packet):
    try:
        # Extract IP layer information
        if 'IP' in packet:
            ip_layer = packet['IP']
            log_packet(f"IP Packet: {ip_layer.src} -> {ip_layer.dst}")

        # Extract TCP layer information
        if 'TCP' in packet:
            tcp_layer = packet['TCP']
            log_packet(f"TCP Segment: {tcp_layer.srcport} -> {tcp_layer.dstport}")

        # Extract UDP layer information
        if 'UDP' in packet:
            udp_layer = packet['UDP']
            log_packet(f"UDP Datagram: {udp_layer.srcport} -> {udp_layer.dstport}")

    except AttributeError as e:
        # Handle packets with missing layers
        pass

# Function to run pyshark capture with a timeout
def pyshark_capture(interface, timeout):
    global running
    capture = pyshark.LiveCapture(interface=interface, bpf_filter='ip')
    try:
        capture.sniff(timeout=timeout)
        for packet in capture.sniff_continuously():
            if not running:
                break
            analyze_packets(packet)
    except asyncio.CancelledError:
        log_packet("Packet capture cancelled")
    except Exception as e:
        log_packet(f"Error during packet capture: {e}")

# Function to start scapy sniffing
def start_scapy_sniffing(interface):
    sniff(prn=packet_handler, iface=interface, stop_filter=lambda x: not running)

# Function to start both scapy and pyshark captures
def start_sniffing():
    global running
    running = True
    interface = interface_combo.get()
    if not interface:
        log_packet("Please select a valid interface.")
        return

    scapy_thread = threading.Thread(target=start_scapy_sniffing, args=(interface,))
    pyshark_thread = threading.Thread(target=pyshark_capture, args=(interface, 10))

    scapy_thread.start()
    pyshark_thread.start()

    sniffing_threads.append(scapy_thread)
    sniffing_threads.append(pyshark_thread)

# Function to stop sniffing
def stop_sniffing():
    global running
    running = False
    for thread in sniffing_threads:
        if thread.is_alive():
            thread.join()
    log_packet("Sniffing stopped.")

# Function to log packets in the text area
def log_packet(packet_info):
    text_area.configure(state='normal')
    text_area.insert(tk.END, packet_info + "\n")
    text_area.configure(state='disabled')
    text_area.yview(tk.END)

# Create the GUI
app = tk.Tk()
app.title("Packet Sniffer")
app.geometry("800x600")

interface_label = tk.Label(app, text="Network Interface:")
interface_label.pack(pady=5)

interface_combo = ttk.Combobox(app)
interface_combo['values'] = get_if_list()
interface_combo.pack(pady=5)

start_button = tk.Button(app, text="Start Sniffing", command=start_sniffing)
start_button.pack(pady=5)

stop_button = tk.Button(app, text="Stop Sniffing", command=stop_sniffing)
stop_button.pack(pady=5)

text_area = scrolledtext.ScrolledText(app, state='disabled', width=100, height=30)
text_area.pack(pady=10)

sniffing_threads = []

app.mainloop()
