import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import queue
from scapy.all import sniff, hexdump, Raw, Ether, IP, TCP, UDP, ICMP, DNS, ARP, get_if_list
import time
import re
import urllib.parse
from collections import defaultdict
import json
import ctypes
import os
import sys

# --- Enhanced Theme and Styling ---
THEME = {
    "bg": "#1e1e1e",
    "fg": "#ffffff",
    "widget_bg": "#2d2d2d",
    "select_bg": "#007acc",
    "header_bg": "#007acc",
    "button_bg": "#0e639c",
    "button_fg": "#ffffff",
    "entry_bg": "#3c3c3c",
    "success": "#4ec9b0",
    "warning": "#ffcc02",
    "error": "#f44747"
}

def extract_http_info(packet):
    """Extract HTTP information from packets"""
    http_info = {}
    if packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode('utf-8', 'ignore')
            lines = payload.split('\r\n')
            
            # HTTP Request
            if lines[0].startswith(('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS')):
                parts = lines[0].split(' ')
                if len(parts) >= 3:
                    http_info['method'] = parts[0]
                    http_info['path'] = parts[1]
                    http_info['version'] = parts[2]
                
                # Extract Host header
                for line in lines[1:]:
                    if line.lower().startswith('host:'):
                        http_info['host'] = line.split(':', 1)[1].strip()
                        break
                
                # Construct full URL
                if 'host' in http_info and 'path' in http_info:
                    http_info['url'] = f"http://{http_info['host']}{http_info['path']}"
                    
            # HTTP Response
            elif lines[0].startswith('HTTP/'):
                parts = lines[0].split(' ', 2)
                if len(parts) >= 3:
                    http_info['version'] = parts[0]
                    http_info['status_code'] = parts[1]
                    http_info['status_text'] = parts[2]
                    
        except Exception:
            pass
    return http_info

def extract_dns_info(packet):
    """Extract DNS query information"""
    dns_info = {}
    if packet.haslayer(DNS):
        dns = packet[DNS]
        if dns.qr == 0:  # Query
            if dns.qd:
                dns_info['query'] = dns.qd.qname.decode('utf-8', 'ignore').rstrip('.')
                dns_info['type'] = 'Query'
        else:  # Response
            if dns.qd:
                dns_info['query'] = dns.qd.qname.decode('utf-8', 'ignore').rstrip('.')
                dns_info['type'] = 'Response'
                if dns.an:
                    dns_info['answers'] = []
                    for i in range(dns.ancount):
                        if hasattr(dns.an[i], 'rdata'):
                            dns_info['answers'].append(str(dns.an[i].rdata))
    return dns_info

def get_packet_info(packet):
    """Generates a summary string for the 'Info' column, similar to Wireshark."""
    info_parts = []
    
    # HTTP Traffic
    http_info = extract_http_info(packet)
    if http_info:
        if 'method' in http_info:
            info_parts.append(f"HTTP {http_info['method']} {http_info.get('path', '')}")
            if 'host' in http_info:
                info_parts.append(f"Host: {http_info['host']}")
        elif 'status_code' in http_info:
            info_parts.append(f"HTTP {http_info['status_code']} {http_info.get('status_text', '')}")
        return " ".join(info_parts)
    
    # DNS Traffic
    dns_info = extract_dns_info(packet)
    if dns_info:
        if dns_info['type'] == 'Query':
            info_parts.append(f"DNS Query: {dns_info['query']}")
        else:
            info_parts.append(f"DNS Response: {dns_info['query']}")
            if 'answers' in dns_info and dns_info['answers']:
                info_parts.append(f"→ {', '.join(dns_info['answers'][:2])}")
        return " ".join(info_parts)
    
    # TCP Traffic
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        info_parts.append(f"{tcp.sport} → {tcp.dport}")
        
        # Add flag information
        flags = []
        if tcp.flags.S: flags.append("SYN")
        if tcp.flags.A: flags.append("ACK") 
        if tcp.flags.F: flags.append("FIN")
        if tcp.flags.R: flags.append("RST")
        if tcp.flags.P: flags.append("PSH")
        if flags:
            info_parts.append(f"[{','.join(flags)}]")
        
        info_parts.append(f"Seq={tcp.seq} Len={len(tcp.payload)}")
        
        # Check for common protocols
        if tcp.dport == 80 or tcp.sport == 80:
            info_parts.append("HTTP")
        elif tcp.dport == 443 or tcp.sport == 443:
            info_parts.append("HTTPS")
        elif tcp.dport == 21 or tcp.sport == 21:
            info_parts.append("FTP")
        elif tcp.dport == 22 or tcp.sport == 22:
            info_parts.append("SSH")
        elif tcp.dport == 23 or tcp.sport == 23:
            info_parts.append("Telnet")
            
    # UDP Traffic
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        info_parts.append(f"{udp.sport} → {udp.dport}")
        info_parts.append(f"Len={len(udp.payload)}")
        
        # Check for common UDP protocols
        if udp.dport == 53 or udp.sport == 53:
            info_parts.append("DNS")
        elif udp.dport == 67 or udp.sport == 67 or udp.dport == 68 or udp.sport == 68:
            info_parts.append("DHCP")
        elif udp.dport == 123 or udp.sport == 123:
            info_parts.append("NTP")
            
    # ARP Traffic
    elif packet.haslayer(ARP):
        arp = packet[ARP]
        if arp.op == 1:
            info_parts.append(f"Who has {arp.pdst}? Tell {arp.psrc}")
        else:
            info_parts.append(f"{arp.psrc} is at {arp.hwsrc}")
            
    # ICMP Traffic
    elif packet.haslayer(ICMP):
        icmp = packet[ICMP]
        icmp_types = {0: "Echo Reply", 8: "Echo Request", 3: "Destination Unreachable", 11: "Time Exceeded"}
        icmp_type = icmp_types.get(icmp.type, f"Type {icmp.type}")
        info_parts.append(f"ICMP {icmp_type}")
        
    return " ".join(info_parts)

def format_packet_details(packet):
    """Creates a well-formatted, multi-line string of all packet details."""
    details = []
    
    # Packet Summary
    details.append(f"=== PACKET SUMMARY ===")
    details.append(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet.time))}")
    details.append(f"Size: {len(packet)} bytes")
    details.append("")
    
    # Ethernet Layer
    if packet.haslayer(Ether):
        ether = packet[Ether]
        details.append(f"=== ETHERNET II ===")
        details.append(f"   Destination: {ether.dst}")
        details.append(f"   Source: {ether.src}")
        details.append(f"   Type: {hex(ether.type)} ({ether.type})")
        details.append("")
    
    # IP Layer
    if packet.haslayer(IP):
        ip = packet[IP]
        details.append(f"=== IPv4 ===")
        details.append(f"   Version: {ip.version}")
        details.append(f"   Header Length: {ip.ihl * 4} bytes")
        details.append(f"   Type of Service: 0x{ip.tos:02x}")
        details.append(f"   Total Length: {ip.len}")
        details.append(f"   Identification: {ip.id}")
        details.append(f"   Flags: {ip.flags}")
        details.append(f"   Fragment Offset: {ip.frag}")
        details.append(f"   Time to Live: {ip.ttl}")
        details.append(f"   Protocol: {ip.proto}")
        details.append(f"   Header Checksum: 0x{ip.chksum:04x}")
        details.append(f"   Source: {ip.src}")
        details.append(f"   Destination: {ip.dst}")
        details.append("")
    
    # TCP Layer
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        details.append(f"=== TCP ===")
        details.append(f"   Source Port: {tcp.sport}")
        details.append(f"   Destination Port: {tcp.dport}")
        details.append(f"   Sequence Number: {tcp.seq}")
        details.append(f"   Acknowledgment Number: {tcp.ack}")
        details.append(f"   Header Length: {tcp.dataofs * 4} bytes")
        details.append(f"   Flags: {tcp.flags.flagrepr()}")
        details.append(f"   Window Size: {tcp.window}")
        details.append(f"   Checksum: 0x{tcp.chksum:04x}")
        details.append(f"   Urgent Pointer: {tcp.urgptr}")
        details.append("")
        
        # Check for HTTP traffic
        http_info = extract_http_info(packet)
        if http_info:
            details.append(f"=== HTTP ===")
            for key, value in http_info.items():
                details.append(f"   {key.replace('_', ' ').title()}: {value}")
            details.append("")
    
    # UDP Layer
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        details.append(f"=== UDP ===")
        details.append(f"   Source Port: {udp.sport}")
        details.append(f"   Destination Port: {udp.dport}")
        details.append(f"   Length: {udp.len}")
        details.append(f"   Checksum: 0x{udp.chksum:04x}")
        details.append("")
        
        # Check for DNS traffic
        dns_info = extract_dns_info(packet)
        if dns_info:
            details.append(f"=== DNS ===")
            for key, value in dns_info.items():
                if key == 'answers' and isinstance(value, list):
                    details.append(f"   Answers: {', '.join(value)}")
                else:
                    details.append(f"   {key.replace('_', ' ').title()}: {value}")
            details.append("")
    
    # ARP Layer
    elif packet.haslayer(ARP):
        arp = packet[ARP]
        details.append(f"=== ARP ===")
        details.append(f"   Hardware Type: {arp.hwtype}")
        details.append(f"   Protocol Type: {arp.ptype}")
        details.append(f"   Hardware Size: {arp.hwlen}")
        details.append(f"   Protocol Size: {arp.plen}")
        details.append(f"   Opcode: {arp.op} ({'Request' if arp.op == 1 else 'Reply'})")
        details.append(f"   Sender MAC: {arp.hwsrc}")
        details.append(f"   Sender IP: {arp.psrc}")
        details.append(f"   Target MAC: {arp.hwdst}")
        details.append(f"   Target IP: {arp.pdst}")
        details.append("")
    
    # ICMP Layer
    elif packet.haslayer(ICMP):
        icmp = packet[ICMP]
        details.append(f"=== ICMP ===")
        details.append(f"   Type: {icmp.type}")
        details.append(f"   Code: {icmp.code}")
        details.append(f"   Checksum: 0x{icmp.chksum:04x}")
        details.append(f"   ID: {icmp.id}")
        details.append(f"   Sequence: {icmp.seq}")
        details.append("")
    
    # Payload
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        details.append(f"=== PAYLOAD ===")
        details.append(f"   Length: {len(payload)} bytes")
        details.append("")
        
        # Try to decode as text
        try:
            text_payload = payload.decode('utf-8', 'ignore')
            if text_payload.strip():
                details.append(f"=== TEXT PAYLOAD ===")
                details.append(text_payload[:1000])  # Limit to first 1000 chars
                details.append("")
        except:
            pass
        
        # Hexdump
        details.append(f"=== HEX DUMP ===")
        hex_dump = hexdump(payload, dump=True)
        details.append(hex_dump)
    
    return "\n".join(details)

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")
        self.root.geometry("800x600")  # Reduced window size
        self.root.minsize(600, 400)  # Set minimum size to ensure status bar is always visible
        self.root.configure(bg=THEME["bg"])
        self.root.bind('<Control-q>', lambda e: self.root.destroy())
        
        # Initialize variables
        self.sniffing = False
        self.paused = False
        self.sniffing_thread = None
        self.packet_queue = queue.Queue()
        self.all_packets_data = []
        self.statistics = defaultdict(int)
        self.captured_urls = set()
        self.dns_queries = set()
        
        # Get available network interfaces
        self.interfaces = self.get_network_interfaces()
        
        self.apply_styles()
        self.create_widgets()
        self.update_gui()
        self.update_statistics()
    
    def get_network_interfaces(self):
        """Get list of available network interfaces with friendly names"""
        try:
            from scapy.all import get_if_list, get_if_addr, conf
            
            interfaces = []
            interface_map = {}
            
            # Get all interfaces
            all_interfaces = get_if_list()
            
            # Try to get friendly names and filter active interfaces
            for iface in all_interfaces:
                try:
                    # Try to get IP address to check if interface is active
                    ip_addr = get_if_addr(iface)
                    if ip_addr and ip_addr != "0.0.0.0":
                        # Create friendly name based on IP and interface type
                        if "loopback" in iface.lower():
                            friendly_name = f"Loopback ({ip_addr})"
                        elif ip_addr.startswith("169.254"):
                            friendly_name = f"Local Link ({ip_addr})"
                        elif ip_addr == "127.0.0.1":
                            friendly_name = f"Loopback ({ip_addr})"
                        else:
                            # This is likely the main network interface
                            friendly_name = f"Network Interface ({ip_addr})"
                        
                        interfaces.append((friendly_name, iface))
                        interface_map[friendly_name] = iface
                        
                except Exception:
                    continue
            
            # If no active interfaces found, add some common names
            if not interfaces:
                common_interfaces = [
                    ("Wi-Fi", "Wi-Fi"),
                    ("Ethernet", "Ethernet"),
                    ("Local Area Connection", "Local Area Connection"),
                    ("Wireless Network Connection", "Wireless Network Connection")
                ]
                interfaces = common_interfaces
                for name, iface in common_interfaces:
                    interface_map[name] = iface
            
            self.interface_map = interface_map
            return interfaces
            
        except Exception as e:
            print(f"Error getting interfaces: {e}")
            # Fallback to common Windows interface names
            common_interfaces = [
                ("Wi-Fi", "Wi-Fi"),
                ("Ethernet", "Ethernet"),
                ("Local Area Connection", "Local Area Connection"),
                ("Wireless Network Connection", "Wireless Network Connection")
            ]
            self.interface_map = {name: iface for name, iface in common_interfaces}
            return common_interfaces

    def apply_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure main styles
        style.configure(".", 
                       background=THEME["bg"], 
                       foreground=THEME["fg"], 
                       fieldbackground=THEME["widget_bg"],
                       selectbackground=THEME["select_bg"])
        
        style.configure("TFrame", background=THEME["bg"])
        style.configure("TLabel", background=THEME["bg"], foreground=THEME["fg"], font=('Segoe UI', 9))
        style.configure("TButton", 
                       background=THEME["button_bg"], 
                       foreground=THEME["button_fg"],
                       font=('Segoe UI', 9, 'bold'),
                       padding=(10, 5))
        style.map("TButton",
                 background=[('active', THEME["select_bg"]),
                            ('pressed', THEME["header_bg"])])
        
        style.configure("TEntry", 
                       fieldbackground=THEME["entry_bg"],
                       foreground=THEME["fg"],
                       font=('Segoe UI', 9))
        
        style.configure("TCombobox",
                       fieldbackground=THEME["entry_bg"],
                       foreground=THEME["fg"],
                       font=('Segoe UI', 9))
        
        style.configure("Treeview.Heading", 
                       background=THEME["header_bg"],
                       foreground=THEME["fg"],
                       font=('Segoe UI', 10, 'bold'))
        
        style.configure("Treeview", 
                       background=THEME["widget_bg"],
                       foreground=THEME["fg"],
                       fieldbackground=THEME["widget_bg"],
                       font=('Segoe UI', 9),
                       rowheight=25)
        
        style.map("Treeview",
                 background=[('selected', THEME["select_bg"])],
                 foreground=[('selected', THEME["fg"])])
        
        # Configure notebook (tabs)
        style.configure("TNotebook", background=THEME["bg"])
        style.configure("TNotebook.Tab", 
                       background=THEME["widget_bg"],
                       foreground=THEME["fg"],
                       font=('Segoe UI', 9))
        style.map("TNotebook.Tab",
                 background=[('selected', THEME["select_bg"])])
        
        # Configure status bar
        style.configure("Status.TLabel",
                       background=THEME["widget_bg"],
                       foreground=THEME["fg"],
                       font=('Segoe UI', 9),
                       relief=tk.FLAT,
                       borderwidth=1)

    def create_widgets(self):
        # Create status bar FIRST - pack it to bottom to reserve space
        self.create_status_bar()
        
        # Create main notebook for tabs AFTER status bar
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=(10, 3))
        
        # Main capture tab
        self.capture_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.capture_frame, text="Packet Capture")
        
        # Statistics tab
        self.stats_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.stats_frame, text="Statistics")
        
        # Web traffic tab
        self.web_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.web_frame, text="Web Traffic")
        
        self.create_capture_tab()
        self.create_stats_tab()
        self.create_web_tab()
    
    def create_capture_tab(self):
        # --- Top Control Frame ---
        top_frame = ttk.Frame(self.capture_frame)
        top_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=(10,5))
        
        # Check administrator privileges
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                # Add warning frame
                warning_frame = ttk.Frame(top_frame)
                warning_frame.pack(fill=tk.X, pady=(0,10))
                
                warning_label = ttk.Label(warning_frame, 
                                        text="⚠ WARNING: Not running as Administrator. Packet capture may fail.",
                                        foreground=THEME["warning"],
                                        font=('Segoe UI', 9, 'bold'))
                warning_label.pack(side=tk.LEFT)
                
                admin_button = ttk.Button(warning_frame, text="Run as Admin", 
                                        command=self.run_as_admin)
                admin_button.pack(side=tk.RIGHT)
        except:
            pass
        
        # --- Interface and Filter Frame ---
        iface_filter_frame = ttk.Frame(top_frame)
        iface_filter_frame.pack(fill=tk.X, pady=(0,10))
        
        # Interface selection
        ttk.Label(iface_filter_frame, text="Interface:").pack(side=tk.LEFT, padx=(0,5))
        self.iface_var = tk.StringVar()
        
        # Create interface display names and store mapping
        self.interface_map = {}
        interface_names = []
        for display_name, actual_name in self.interfaces:
            interface_names.append(display_name)
            self.interface_map[display_name] = actual_name
        
        self.iface_combo = ttk.Combobox(iface_filter_frame, textvariable=self.iface_var, 
                                       values=interface_names, width=35, state="readonly")
        self.iface_combo.pack(side=tk.LEFT, padx=(0,15))
        if interface_names:
            self.iface_combo.set(interface_names[0])
        
        # Filter presets
        ttk.Label(iface_filter_frame, text="Quick Filter:").pack(side=tk.LEFT, padx=(0,5))
        self.filter_preset_var = tk.StringVar()
        filter_presets = [
            "All Traffic",
            "HTTP (port 80)",
            "HTTPS (port 443)",
            "DNS (port 53)",
            "Web Traffic (HTTP/HTTPS)",
            "Custom"
        ]
        self.filter_preset_combo = ttk.Combobox(iface_filter_frame, textvariable=self.filter_preset_var,
                                               values=filter_presets, width=20, state="readonly")
        self.filter_preset_combo.pack(side=tk.LEFT, padx=(0,10))
        self.filter_preset_combo.set("Web Traffic (HTTP/HTTPS)")
        self.filter_preset_combo.bind('<<ComboboxSelected>>', self.on_filter_preset_change)
        
        # Custom filter frame
        filter_frame = ttk.Frame(top_frame)
        filter_frame.pack(fill=tk.X, pady=(0,10))
        
        ttk.Label(filter_frame, text="Custom Filter:").pack(side=tk.LEFT, padx=(0,5))
        self.filter_entry = ttk.Entry(filter_frame, font=('Consolas', 9))
        self.filter_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0,5))
        self.filter_entry.insert(0, "")  # Start with no filter to capture all traffic
        
        # Control buttons frame
        buttons_frame = ttk.Frame(top_frame)
        buttons_frame.pack(fill=tk.X, pady=(0,10))
        
        self.start_button = ttk.Button(buttons_frame, text="🚀 Start Capture", command=self.start_sniffing)
        self.start_button.pack(side=tk.LEFT, padx=(0,5))
        
        self.stop_button = ttk.Button(buttons_frame, text="⏹ Stop Capture", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=(0,5))
        
        self.pause_button = ttk.Button(buttons_frame, text="⏸ Pause", command=self.pause_sniffing, state=tk.DISABLED)
        self.pause_button.pack(side=tk.LEFT, padx=(0,5))
        
        self.clear_button = ttk.Button(buttons_frame, text="🗑 Clear", command=self.clear_display)
        self.clear_button.pack(side=tk.LEFT, padx=(0,5))
        
        self.save_button = ttk.Button(buttons_frame, text="💾 Save", command=self.save_capture)
        self.save_button.pack(side=tk.LEFT, padx=(0,5))
        
        # Add debug button
        debug_button = ttk.Button(buttons_frame, text="🔍 Debug Interfaces", command=self.debug_interfaces)
        debug_button.pack(side=tk.LEFT, padx=(0,5))
        
        # Search frame
        search_frame = ttk.Frame(top_frame)
        search_frame.pack(fill=tk.X)
        
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=(0,5))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", self.filter_packet_list)
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var, font=('Consolas', 9))
        self.search_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0,5))
        
        # Packet count label
        self.packet_count_label = ttk.Label(search_frame, text="Packets: 0")
        self.packet_count_label.pack(side=tk.RIGHT, padx=(5,0))
        
        # Main content area
        content_pane = ttk.PanedWindow(self.capture_frame, orient=tk.VERTICAL)
        content_pane.pack(expand=True, fill=tk.BOTH, padx=10, pady=5)
        
        # Packet list frame
        list_frame = ttk.Frame(content_pane)
        content_pane.add(list_frame, weight=55)
        
        # Treeview with scrollbars
        tree_frame = ttk.Frame(list_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        columns = ("#", "Time", "Source", "Destination", "Protocol", "Length", "Info")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=15)
        
        # Configure columns
        self.tree.column("#", width=60, stretch=False, anchor=tk.CENTER)
        self.tree.column("Time", width=120, stretch=False, anchor=tk.CENTER)
        self.tree.column("Source", width=140, stretch=False, anchor=tk.CENTER)
        self.tree.column("Destination", width=140, stretch=False, anchor=tk.CENTER)
        self.tree.column("Protocol", width=80, stretch=False, anchor=tk.CENTER)
        self.tree.column("Length", width=80, stretch=False, anchor=tk.CENTER)
        self.tree.column("Info", width=600, stretch=True)
        
        # Configure headings
        for col in columns:
            self.tree.heading(col, text=col, command=lambda c=col: self.sort_treeview(c))
        
        # Add scrollbars
        v_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        
        self.tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        self.tree.grid(row=0, column=0, sticky="nsew")
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        h_scrollbar.grid(row=1, column=0, sticky="ew")
        
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        
        self.tree.bind("<<TreeviewSelect>>", self.show_packet_details)
        self.tree.bind("<Double-1>", self.on_packet_double_click)
        
        # Packet details frame
        details_frame = ttk.Frame(content_pane)
        content_pane.add(details_frame, weight=45)
        
        details_label = ttk.Label(details_frame, text="Packet Details", font=('Segoe UI', 11, 'bold'))
        details_label.pack(anchor=tk.W, pady=(0,5))
        
        self.details_text = scrolledtext.ScrolledText(
            details_frame, 
            wrap=tk.WORD, 
            state=tk.DISABLED,
            bg=THEME["widget_bg"],
            fg=THEME["fg"],
            font=("Consolas", 10),
            insertbackground=THEME["fg"]
        )
        self.details_text.pack(expand=True, fill=tk.BOTH)
        
        # Configure text tags for syntax highlighting
        self.details_text.tag_configure("header", foreground=THEME["success"], font=("Consolas", 10, "bold"))
        self.details_text.tag_configure("value", foreground=THEME["warning"])
        self.details_text.tag_configure("important", foreground=THEME["error"], font=("Consolas", 10, "bold"))
    
    def create_stats_tab(self):
        # Statistics display
        stats_main_frame = ttk.Frame(self.stats_frame)
        stats_main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Statistics text area
        stats_label = ttk.Label(stats_main_frame, text="Live Statistics", font=('Segoe UI', 12, 'bold'))
        stats_label.pack(anchor=tk.W, pady=(0,10))
        
        self.stats_text = scrolledtext.ScrolledText(
            stats_main_frame,
            wrap=tk.WORD,
            state=tk.DISABLED,
            bg=THEME["widget_bg"],
            fg=THEME["fg"],
            font=("Consolas", 10),
            height=20
        )
        self.stats_text.pack(fill=tk.BOTH, expand=True)
    
    def create_web_tab(self):
        # Web traffic analysis
        web_main_frame = ttk.Frame(self.web_frame)
        web_main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # URLs section
        urls_label = ttk.Label(web_main_frame, text="Captured URLs", font=('Segoe UI', 12, 'bold'))
        urls_label.pack(anchor=tk.W, pady=(0,5))
        
        self.urls_text = scrolledtext.ScrolledText(
            web_main_frame,
            wrap=tk.WORD,
            state=tk.DISABLED,
            bg=THEME["widget_bg"],
            fg=THEME["fg"],
            font=("Segoe UI", 10),
            height=12
        )
        self.urls_text.pack(fill=tk.BOTH, expand=True, pady=(0,10))
        
        # DNS queries section
        dns_label = ttk.Label(web_main_frame, text="DNS Queries", font=('Segoe UI', 12, 'bold'))
        dns_label.pack(anchor=tk.W, pady=(0,5))
        
        self.dns_text = scrolledtext.ScrolledText(
            web_main_frame,
            wrap=tk.WORD,
            state=tk.DISABLED,
            bg=THEME["widget_bg"],
            fg=THEME["fg"],
            font=("Segoe UI", 10),
            height=12
        )
        self.dns_text.pack(fill=tk.BOTH, expand=True)
    
    def create_status_bar(self):
        # Create status bar frame with distinct background
        self.status_frame = ttk.Frame(self.root)
        # Pack the status bar frame at the bottom of the root window FIRST
        self.status_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=1)

        # Copyright label centered in the status bar
        self.copyright_label = ttk.Label(self.status_frame, text="© 2025 Packet Sniffer - Made by Umair",
                                        font=('Segoe UI', 9, 'italic'),
                                        anchor=tk.CENTER)
        # Center the copyright label with proper expansion
        self.copyright_label.pack(expand=True, fill=tk.X, pady=1)

        # Create invisible status labels for compatibility (but don't display them)
        self.status_label = ttk.Label(self.status_frame, text="", style="Status.TLabel")
        self.capture_status_label = ttk.Label(self.status_frame, text="", style="Status.TLabel")

    def on_filter_preset_change(self, event=None):
        """Handle filter preset selection"""
        preset = self.filter_preset_var.get()
        filter_map = {
            "All Traffic": "",
            "HTTP (port 80)": "tcp port 80",
            "HTTPS (port 443)": "tcp port 443", 
            "DNS (port 53)": "udp port 53",
            "Web Traffic (HTTP/HTTPS)": "tcp port 80 or tcp port 443 or udp port 53",
            "Custom": self.filter_entry.get()
        }
        
        if preset != "Custom" and preset in filter_map:
            self.filter_entry.delete(0, tk.END)
            self.filter_entry.insert(0, filter_map[preset])
    
    def run_as_admin(self):
        """Run the application as administrator"""
        try:
            import subprocess
            import sys
            import os
            
            # Get the current script path
            script_path = os.path.abspath(__file__)
            
            # Run the script as administrator
            subprocess.run([
                'powershell', 
                '-Command', 
                f'Start-Process python -ArgumentList "{script_path}" -Verb RunAs'
            ], shell=True)
            
            # Close current instance
            self.root.destroy()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to run as administrator: {e}")
    
    def start_sniffing(self):
        """Start packet capture with improved error handling"""
        if self.sniffing:
            return
            
        selected_display = self.iface_var.get()
        if not selected_display:
            messagebox.showerror("Error", "Please select a network interface")
            return
        
        # Get actual interface name
        actual_interface = self.interface_map.get(selected_display, selected_display)
        
        # Clear previous data
        self.clear_display()
        
        try:
            self.sniffing = True
            self.paused = False
            self.toggle_controls(active=True)
            
            # Update status
            self.update_status("Starting capture...", "Starting")
            
            # Get filter
            filter_str = self.filter_entry.get().strip()
            
            # Start sniffing in a separate thread
            sniff_kwargs = {
                'prn': self.packet_handler,
                'filter': filter_str if filter_str else None,
                'iface': actual_interface,
                'store': False,
                'stop_filter': lambda p: not self.sniffing
            }
            
            self.sniffing_thread = threading.Thread(
                target=self.sniff_with_error_handling, 
                args=(sniff_kwargs,), 
                daemon=True
            )
            self.sniffing_thread.start()
            
            self.update_status(f"Capturing on {selected_display}", "Running")
            
        except Exception as e:
            self.sniffing = False
            self.toggle_controls(active=False)
            messagebox.showerror("Capture Error", f"Failed to start capture: {e}")
            self.update_status("Error starting capture", "Stopped")
    
    def sniff_with_error_handling(self, sniff_kwargs):
        """Wrapper for sniff with error handling"""
        try:
            from scapy.all import sniff
            sniff(**sniff_kwargs)
        except Exception as e:
            self.handle_sniff_error(str(e))
    
    def handle_sniff_error(self, error_msg):
        """Handle sniffing errors"""
        self.sniffing = False
        self.root.after(0, lambda: self.toggle_controls(active=False))
        self.root.after(0, lambda: self.update_status("Capture failed", "Error"))
        
        # Show error message in main thread
        self.root.after(0, lambda: messagebox.showerror(
            "Capture Error", 
            f"Packet capture failed:\n{error_msg}\n\nTry:\n• Running as Administrator\n• Installing Npcap\n• Selecting a different interface"
        ))
    
    def packet_handler(self, packet):
        """Handle captured packets"""
        if not self.sniffing or self.paused:
            return
            
        try:
            # Add packet to queue for GUI processing
            self.packet_queue.put(packet)
            
            # Update statistics
            self.statistics['total_packets'] += 1
            self.statistics['total_bytes'] += len(packet)  # Add packet size to total bytes
            
            # Track protocol statistics
            if packet.haslayer('TCP'):
                self.statistics['tcp_packets'] += 1
            elif packet.haslayer('UDP'):
                self.statistics['udp_packets'] += 1
            elif packet.haslayer('ICMP'):
                self.statistics['icmp_packets'] += 1
            elif packet.haslayer('ARP'):
                self.statistics['arp_packets'] += 1
            
            # Extract web traffic information
            http_info = extract_http_info(packet)
            if http_info and 'url' in http_info:
                self.captured_urls.add(http_info['url'])
            
            dns_info = extract_dns_info(packet)
            if dns_info and 'query' in dns_info:
                self.dns_queries.add(dns_info['query'])
                
        except Exception as e:
            print(f"Error processing packet: {e}")
    
    def pause_sniffing(self):
        """Pause/resume packet capture"""
        if not self.sniffing:
            return
            
        self.paused = not self.paused
        status = "Paused" if self.paused else "Running"
        button_text = "▶ Resume" if self.paused else "⏸ Pause"
        
        self.pause_button.config(text=button_text)
        self.update_status(f"Capture {status.lower()}", status)
    
    def stop_sniffing(self):
        """Stop packet capture"""
        self.sniffing = False
        self.paused = False
        self.toggle_controls(active=False)
        self.update_status("Capture stopped", "Stopped")
    
    def toggle_controls(self, active):
        """Enable/disable controls based on capture state"""
        state = "disabled" if active else "normal"
        self.start_button.config(state=state)
        self.filter_entry.config(state=state)
        self.iface_combo.config(state=state)
        self.filter_preset_combo.config(state=state)
        
        self.stop_button.config(state="normal" if active else "disabled")
        self.pause_button.config(state="normal" if active else "disabled")
        
        if not active:
            self.pause_button.config(text="⏸ Pause")
    
    def clear_display(self):
        """Clear all captured data"""
        self.tree.delete(*self.tree.get_children())
        self.all_packets_data.clear()
        self.statistics.clear()
        self.captured_urls.clear()
        self.dns_queries.clear()
        
        # Clear details
        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete(1.0, tk.END)
        self.details_text.config(state=tk.DISABLED)
        
        # Reset search
        self.search_var.set("")
        
        self.update_status("Display cleared", "Stopped")
    
    def save_capture(self):
        """Save captured packets to file"""
        if not self.all_packets_data:
            messagebox.showwarning("Warning", "No packets to save")
            return
        
        try:
            from tkinter import filedialog
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("JSON files", "*.json"), ("All files", "*.*")]
            )
            
            if filename:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"Packet Capture Report\n")
                    f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Total Packets: {len(self.all_packets_data)}\n")
                    f.write("=" * 50 + "\n\n")
                    
                    for i, data in enumerate(self.all_packets_data, 1):
                        packet = data['packet']
                        f.write(f"Packet {i}:\n")
                        f.write(f"  Time: {data['values'][1]}\n")
                        f.write(f"  Source: {data['values'][2]}\n")
                        f.write(f"  Destination: {data['values'][3]}\n")
                        f.write(f"  Protocol: {data['values'][4]}\n")
                        f.write(f"  Length: {data['values'][5]}\n")
                        f.write(f"  Info: {data['values'][6]}\n")
                        f.write("\n")
                
                messagebox.showinfo("Success", f"Packets saved to {filename}")
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save capture: {e}")
    
    def sort_treeview(self, column):
        """Sort treeview by column"""
        items = [(self.tree.set(child, column), child) for child in self.tree.get_children('')]
        
        # Try to sort numerically if possible
        try:
            items.sort(key=lambda x: float(x[0]) if x[0].replace('.', '').isdigit() else x[0])
        except:
            items.sort()
        
        # Rearrange items
        for index, (val, child) in enumerate(items):
            self.tree.move(child, '', index)
    
    def on_packet_double_click(self, event):
        """Handle double-click on packet"""
        selected_iid = self.tree.focus()
        if selected_iid:
            # Switch to details view or show popup
            self.notebook.select(0)  # Select capture tab
    
    def update_status(self, status, capture_status):
        """Update status bar - now just maintains compatibility"""
        # Status labels are hidden, so this method does nothing but maintains compatibility
        pass
    
    def update_statistics(self):
        """Update statistics display"""
        if hasattr(self, 'stats_text'):
            stats_content = []
            stats_content.append("PACKET CAPTURE STATISTICS")
            stats_content.append("=" * 40)
            stats_content.append("")
            
            # Basic statistics
            stats_content.append("BASIC STATISTICS:")
            stats_content.append("-" * 20)
            stats_content.append(f"Total Packets: {self.statistics.get('total_packets', 0)}")
            stats_content.append(f"Total Bytes: {self.statistics.get('total_bytes', 0)}")
            stats_content.append("")
            
            # Protocol breakdown
            stats_content.append("PROTOCOL BREAKDOWN:")
            stats_content.append("-" * 20)
            stats_content.append(f"TCP Packets: {self.statistics.get('tcp_packets', 0)}")
            stats_content.append(f"UDP Packets: {self.statistics.get('udp_packets', 0)}")
            stats_content.append(f"ICMP Packets: {self.statistics.get('icmp_packets', 0)}")
            stats_content.append(f"ARP Packets: {self.statistics.get('arp_packets', 0)}")
            stats_content.append("")
            
            # Web traffic summary
            stats_content.append("WEB TRAFFIC SUMMARY:")
            stats_content.append("-" * 20)
            stats_content.append(f"Unique URLs Captured: {len(self.captured_urls)}")
            stats_content.append(f"DNS Queries: {len(self.dns_queries)}")
            stats_content.append("")
            
            # Top domains
            if self.dns_queries:
                stats_content.append("TOP DNS QUERIES:")
                stats_content.append("-" * 20)
                for query in list(self.dns_queries)[:10]:  # Show top 10
                    stats_content.append(f"  {query}")
                stats_content.append("")
            
            # Update statistics text
            self.stats_text.config(state=tk.NORMAL)
            
            # Store current scroll position
            current_position = self.stats_text.yview()[0]
            
            self.stats_text.delete(1.0, tk.END)
            self.stats_text.insert(tk.END, "\n".join(stats_content))
            
            # Restore scroll position if user hasn't scrolled to bottom
            if current_position < 0.9:  # If not near bottom, restore position
                self.stats_text.yview_moveto(current_position)
            
            self.stats_text.config(state=tk.DISABLED)
        
        # Update web traffic tab
        if hasattr(self, 'urls_text'):
            # Update URLs
            self.urls_text.config(state=tk.NORMAL)
            
            # Store current scroll position for URLs
            urls_current_position = self.urls_text.yview()[0]
            
            self.urls_text.delete(1.0, tk.END)
            
            if self.captured_urls:
                urls_content = []
                urls_content.append("CAPTURED HTTP URLs:")
                urls_content.append("=" * 30)
                urls_content.append("")
                
                for url in sorted(self.captured_urls):
                    urls_content.append(f"🌐 {url}")
                
                self.urls_text.insert(tk.END, "\n".join(urls_content))
            else:
                self.urls_text.insert(tk.END, "No HTTP URLs captured yet.\n\nTo capture URLs:\n1. Start packet capture\n2. Browse websites\n3. URLs will appear here automatically")
            
            # Restore scroll position if user hasn't scrolled to bottom
            if urls_current_position < 0.9:
                self.urls_text.yview_moveto(urls_current_position)
            
            self.urls_text.config(state=tk.DISABLED)
            
            # Update DNS queries
            self.dns_text.config(state=tk.NORMAL)
            
            # Store current scroll position for DNS
            dns_current_position = self.dns_text.yview()[0]
            
            self.dns_text.delete(1.0, tk.END)
            
            if self.dns_queries:
                dns_content = []
                dns_content.append("DNS QUERIES:")
                dns_content.append("=" * 20)
                dns_content.append("")
                
                for query in sorted(self.dns_queries):
                    dns_content.append(f"🔍 {query}")
                
                self.dns_text.insert(tk.END, "\n".join(dns_content))
            else:
                self.dns_text.insert(tk.END, "No DNS queries captured yet.\n\nDNS queries will appear here when:\n- Websites are visited\n- Domain names are resolved\n- Network requests are made")
            
            # Restore scroll position if user hasn't scrolled to bottom
            if dns_current_position < 0.9:
                self.dns_text.yview_moveto(dns_current_position)
            
            self.dns_text.config(state=tk.DISABLED)
        
        # Update packet count
        if hasattr(self, 'packet_count_label'):
            self.packet_count_label.config(text=f"Packets: {len(self.all_packets_data)}")
        
        # Schedule next update
        self.root.after(2000, self.update_statistics)  # Update every 2 seconds

    def update_gui(self):
        """Update GUI with new packets"""
        try:
            packets_processed = 0
            while not self.packet_queue.empty() and packets_processed < 10:  # Limit processing
                packet = self.packet_queue.get_nowait()
                pkt_time = time.strftime('%H:%M:%S', time.localtime(packet.time))
                
                # Extract packet information
                src, dst, proto, info = "N/A", "N/A", "Unknown", get_packet_info(packet)
                
                if packet.haslayer(IP):
                    src, dst = packet[IP].src, packet[IP].dst
                elif packet.haslayer(Ether):
                    src, dst = packet[Ether].src, packet[Ether].dst
                
                # Determine protocol
                if packet.haslayer(TCP):
                    proto = "TCP"
                elif packet.haslayer(UDP):
                    proto = "UDP"
                elif packet.haslayer(ICMP):
                    proto = "ICMP"
                elif packet.haslayer(ARP):
                    proto = "ARP"
                elif packet.haslayer(DNS):
                    proto = "DNS"
                
                # Add to packet data
                packet_data = {
                    'packet': packet,
                    'values': (len(self.all_packets_data) + 1, pkt_time, src, dst, proto, len(packet), info)
                }
                self.all_packets_data.append(packet_data)
                packets_processed += 1
            
            # Update the display
            self.filter_packet_list()
            
        except queue.Empty:
            pass
        except Exception as e:
            print(f"Error updating GUI: {e}")
        finally:
            self.root.after(100, self.update_gui)  # Update every 100ms

    def filter_packet_list(self, *args):
        """Filter packet list based on search term"""
        search_term = self.search_var.get().lower()
        items_to_show = []
        
        for data in self.all_packets_data:
            if search_term in ' '.join(map(str, data['values'])).lower():
                items_to_show.append(data)
        
        # Clear and repopulate tree
        self.tree.delete(*self.tree.get_children())
        for data in items_to_show:
            self.tree.insert("", "end", iid=data['values'][0], values=data['values'])
        
        # Auto-scroll to bottom only if search is empty (showing all packets)
        # and we're capturing new packets
        if items_to_show and not self.search_var.get() and self.sniffing:
            try:
                last_item = self.tree.get_children()[-1]
                self.tree.see(last_item)
            except:
                pass

    def show_packet_details(self, event=None):
        """Show detailed packet information"""
        selected_iid = self.tree.focus()
        if not selected_iid:
            return
            
        try:
            packet_obj = next((p['packet'] for p in self.all_packets_data if p['values'][0] == int(selected_iid)), None)
            if packet_obj:
                details_str = format_packet_details(packet_obj)
                self.details_text.config(state=tk.NORMAL)
                self.details_text.delete(1.0, tk.END)
                self.details_text.insert(tk.END, details_str)
                self.details_text.config(state=tk.DISABLED)
        except Exception as e:
            print(f"Error showing packet details: {e}")

    def debug_interfaces(self):
        """Debug function to show interface information"""
        try:
            from scapy.all import get_if_list, get_if_addr, conf
            import subprocess
            
            debug_info = []
            debug_info.append("=== NETWORK INTERFACE DEBUG ===")
            debug_info.append("")
            
            # Check admin privileges
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            debug_info.append(f"Running as Administrator: {is_admin}")
            debug_info.append("")
            
            # Scapy interfaces
            debug_info.append("SCAPY INTERFACES:")
            debug_info.append("-" * 30)
            try:
                interfaces = get_if_list()
                for i, iface in enumerate(interfaces):
                    try:
                        ip_addr = get_if_addr(iface)
                        debug_info.append(f"{i+1}. {iface}")
                        debug_info.append(f"   IP: {ip_addr}")
                    except:
                        debug_info.append(f"{i+1}. {iface}")
                        debug_info.append(f"   IP: Unable to get IP")
                    debug_info.append("")
            except Exception as e:
                debug_info.append(f"Error getting Scapy interfaces: {e}")
            
            # Windows ipconfig output
            debug_info.append("WINDOWS NETWORK INTERFACES:")
            debug_info.append("-" * 30)
            try:
                result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True)
                # Parse and show only relevant parts
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'adapter' in line.lower() or 'connection' in line.lower():
                        debug_info.append(line.strip())
                    elif 'IPv4 Address' in line:
                        debug_info.append(f"  {line.strip()}")
                    elif 'Media State' in line:
                        debug_info.append(f"  {line.strip()}")
            except Exception as e:
                debug_info.append(f"Error getting Windows interfaces: {e}")
            
            debug_info.append("")
            debug_info.append("RECOMMENDATIONS:")
            debug_info.append("-" * 20)
            if not is_admin:
                debug_info.append("• Run as Administrator for packet capture")
            debug_info.append("• Use 'Wi-Fi' for wireless connections")
            debug_info.append("• Use 'Ethernet' for wired connections")
            debug_info.append("• Install Npcap if not already installed")
            debug_info.append("• Check Windows Defender/Antivirus settings")
            
            # Show debug info in a popup
            debug_window = tk.Toplevel(self.root)
            debug_window.title("Network Interface Debug")
            debug_window.geometry("800x600")
            debug_window.configure(bg=THEME["bg"])
            
            debug_text = scrolledtext.ScrolledText(
                debug_window,
                wrap=tk.WORD,
                bg=THEME["widget_bg"],
                fg=THEME["fg"],
                font=("Consolas", 10)
            )
            debug_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            debug_text.insert(tk.END, "\n".join(debug_info))
            debug_text.config(state=tk.DISABLED)
            
        except Exception as e:
            messagebox.showerror("Debug Error", f"Failed to get debug info: {str(e)}")
    
    # ...existing code...
if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()