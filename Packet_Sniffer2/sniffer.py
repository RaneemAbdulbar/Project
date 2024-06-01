import threading
import tkinter as tk
from tkinter import scrolledtext, ttk
from scapy.all import sniff, get_if_list
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.layers.http import HTTPRequest, HTTPResponse
import pyshark
import queue
import logging
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import socket

#GUI Setup
def setup_gui():
    root = tk.Tk()
    root.title("Packet Sniffer")

    start_button = tk.Button(root, text="Start Sniffing", command=start_sniffing)
    stop_button = tk.Button(root, text="Stop Sniffing", command=stop_sniffing)
    log_area = scrolledtext.ScrolledText(root, wrap=tk.WORD)

    start_button.pack()
    stop_button.pack()
    log_area.pack()

    return root, log_area
    

# Visualization with Matplotlib
def plot_data():
    fig, ax = plt.subplots()
    ax.plot([0, 1, 2, 3], [0, 1, 4, 9])  # Example data

    canvas = FigureCanvasTkAgg(fig, master=root)
    canvas.get_tk_widget().pack()
    canvas.draw()


# Global variables to control the sniffing threads and stopping events
running = False
scapy_stop_event = threading.Event()
pyshark_stop_event = threading.Event()

# Queue to handle logging from threads
log_queue = queue.Queue()

# Traffic statistics
traffic_stats = {
    'total': 0,
    'tcp': 0,
    'udp': 0,
    'icmp': 0,
    'http': 0
}

# Set up logging
logging.basicConfig(filename='packet_sniffer.log', level=logging.INFO)

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
        if packet.haslayer(HTTPRequest):
            http_layer = packet[HTTPRequest]
            log_packet(f"HTTP Request: {http_layer.Host}{http_layer.Path}")
        elif packet.haslayer(HTTPResponse):
            http_layer = packet[HTTPResponse]
            log_packet(f"HTTP Response: {http_layer.Status_Code} {http_layer.Reason_Phrase}")

    if UDP in packet:
        udp_layer = packet[UDP]
        log_packet(f"UDP Datagram: {udp_layer.sport} -> {udp_layer.dport}")

    update_stats(packet)
    check_alerts(packet)

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

    except AttributeError:
        # Handle packets with missing layers
        pass

# Function to run pyshark capture
def pyshark_capture(interface, filter_string):
    global running
    capture = pyshark.LiveCapture(interface=interface, bpf_filter=filter_string)
    try:
        for packet in capture.sniff_continuously():
            if pyshark_stop_event.is_set():
                break
            analyze_packets(packet)
    except Exception as e:
        log_packet(f"Error during packet capture: {e}")

# Function to start scapy sniffing
def start_scapy_sniffing(interface, filter_string):
    sniff(prn=packet_handler, iface=interface, filter=filter_string, stop_filter=lambda x: scapy_stop_event.is_set())

# Function to start both scapy and pyshark captures
def start_sniffing():
    global running
    if running:
        log_packet("Sniffing already in progress.")
        return

    running = True
    interface = interface_combo.get()
    if not interface:
        log_packet("Please select a valid interface.")
        running = False
        return

    filter_string = filter_entry.get()
    
    scapy_stop_event.clear()
    pyshark_stop_event.clear()

    scapy_thread = threading.Thread(target=start_scapy_sniffing, args=(interface, filter_string))
    pyshark_thread = threading.Thread(target=pyshark_capture, args=(interface, filter_string))

    scapy_thread.start()
    pyshark_thread.start()

    sniffing_threads.append(scapy_thread)
    sniffing_threads.append(pyshark_thread)

    log_packet("Started sniffing on interface: " + interface + " with filter: " + filter_string)

# Function to stop sniffing
def stop_sniffing():
    global running
    if not running:
        log_packet("Sniffing is not running.")
        return

    running = False
    scapy_stop_event.set()
    pyshark_stop_event.set()
    for thread in sniffing_threads:
        if thread.is_alive():
            thread.join()
    sniffing_threads.clear()
    log_packet("Sniffing stopped.")

# Function to log packets in the text area
def log_packet(packet_info):
    log_queue.put(packet_info)
    logging.info(packet_info)

# Function to update the text area with logs from the queue
def update_log_text():
    while not log_queue.empty():
        packet_info = log_queue.get()
        text_area.configure(state='normal')
        text_area.insert(tk.END, packet_info + "\n")
        text_area.configure(state='disabled')
        text_area.yview(tk.END)
    stats_label.config(text=f"Total: {traffic_stats['total']}, TCP: {traffic_stats['tcp']}, UDP: {traffic_stats['udp']}, ICMP: {traffic_stats['icmp']}, HTTP: {traffic_stats['http']}")
    app.after(100, update_log_text)

# Function to update traffic statistics
def update_stats(packet):
    traffic_stats['total'] += 1
    if TCP in packet:
        traffic_stats['tcp'] += 1
        if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
            traffic_stats['http'] += 1
    elif UDP in packet:
        traffic_stats['udp'] += 1
    elif ICMP in packet:
        traffic_stats['icmp'] += 1

# Function to check for alerts
def check_alerts(packet):
    if TCP in packet and packet[TCP].dport == 80:
        alert("HTTP traffic detected on port 80")

# Function to handle alerts
def alert(message):
    log_packet(f"ALERT: {message}")

# Function to plot traffic distribution
def plot_traffic_distribution():
    labels = 'TCP', 'UDP', 'ICMP', 'HTTP'
    sizes = [traffic_stats['tcp'], traffic_stats['udp'], traffic_stats['icmp'], traffic_stats['http']]
    colors = ['gold', 'yellowgreen', 'lightcoral', 'lightskyblue']
    explode = (0.1, 0, 0, 0)  # explode the 1st slice (i.e. 'TCP')

    plt.figure(figsize=(5, 5))
    plt.pie(sizes, explode=explode, labels=labels, colors=colors, autopct='%1.1f%%', shadow=True, startangle=140)
    plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
    plt.title("Traffic Distribution")
    plt.show()

# Function to get the local IP address
def get_local_ip():
    try:
        ip = socket.gethostbyname(socket.gethostname())
        ip_label.config(text=f"Your IP Address: {ip}")
    except Exception as e:
        ip_label.config(text=f"Error getting IP Address: {e}")

# Function to clear the text area
def clear_log():
    text_area.configure(state='normal')
    text_area.delete(1.0, tk.END)
    text_area.configure(state='disabled')

# Create the GUI
app = tk.Tk()
app.title("Packet Sniffer")
app.geometry("800x600")

# Create a frame for the controls
control_frame = tk.Frame(app)
control_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nw")

interface_label = tk.Label(control_frame, text="Network Interface:")
interface_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")

interface_combo = ttk.Combobox(control_frame)
interface_combo['values'] = get_if_list()
interface_combo.grid(row=0, column=1, padx=5, pady=5)

filter_label = tk.Label(control_frame, text="Capture Filter:")
filter_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")

filter_entry = tk.Entry(control_frame)
filter_entry.grid(row=1, column=1, padx=5, pady=5)

start_button = tk.Button(control_frame, text="Start Sniffing", command=start_sniffing)
start_button.grid(row=2, column=0, padx=5, pady=5)

stop_button = tk.Button(control_frame, text="Stop Sniffing", command=stop_sniffing)
stop_button.grid(row=2, column=1, padx=5, pady=5)

ip_button = tk.Button(control_frame, text="Get IP Address", command=get_local_ip)
ip_button.grid(row=2, column=2, padx=5, pady=5)

plot_button = tk.Button(control_frame, text="Plot Traffic Distribution", command=plot_traffic_distribution)
plot_button.grid(row=2, column=3, padx=5, pady=5)

clear_button = tk.Button(control_frame, text="Clear Log", command=clear_log)
clear_button.grid(row=2, column=4, padx=5, pady=5)

ip_label = tk.Label(control_frame, text="Your IP Address: ")
ip_label.grid(row=3, column=0, columnspan=5, padx=5, pady=5)

# Create a text area for logging
text_area = scrolledtext.ScrolledText(app, state='disabled', width=100, height=30)
text_area.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")

# Create a label for traffic statistics
stats_label = tk.Label(app, text="Total: 0, TCP: 0, UDP: 0, ICMP: 0, HTTP: 0")
stats_label.grid(row=2, column=0, padx=10, pady=5, sticky="w")

# Configure the grid to expand the text area
app.grid_rowconfigure(1, weight=1)
app.grid_columnconfigure(0, weight=1)

sniffing_threads = []

# Start the log update loop
app.after(100, update_log_text)

app.mainloop()
