import socket  # Добавьте эту строку в начало файла
import tkinter as tk
from tkinter import scrolledtext, ttk, messagebox, filedialog
import psutil
import pickle
import os
import platform
class GUIManager:
    COLUMNS = ('No', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info')

    def __init__(self, root, analyzer):
        self.root = root
        self.analyzer = analyzer
        self.setup_ui()

    def setup_ui(self):
        # Interface selection
        self.interface_label = tk.Label(self.root, text="Select Network Interface:")
        self.interface_label.grid(row=0, column=0, padx=5, pady=5, sticky='w')

        self.interface_combo = ttk.Combobox(self.root, values=self.get_interface_names())
        self.interface_combo.grid(row=0, column=1, padx=5, pady=5, sticky='ew')

        # Filter setup
        self.filter_label = tk.Label(self.root, text="Filter (e.g., tcp, udp, port 80):")
        self.filter_label.grid(row=1, column=0, padx=5, pady=5, sticky='w')

        self.filter_text = tk.StringVar()
        self.filter_entry = tk.Entry(self.root, textvariable=self.filter_text)
        self.filter_entry.grid(row=1, column=1, padx=5, pady=5, sticky='ew')
        self.filter_text.trace_add('write', self.apply_filter)

        # Packet list (treeview)
        self.packet_tree = ttk.Treeview(self.root, columns=self.COLUMNS, show='headings')
        for col in self.COLUMNS:
            self.packet_tree.heading(col, text=col)
            self.packet_tree.column(col, width=100)

        self.packet_tree.column('No', width=50)
        self.packet_tree.column('Time', width=100)
        self.packet_tree.column('Source', width=150)
        self.packet_tree.column('Destination', width=150)
        self.packet_tree.column('Protocol', width=80)
        self.packet_tree.column('Length', width=80)
        self.packet_tree.column('Info', width=300)

        self.packet_tree.grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky='nsew')
        self.packet_tree.tag_configure('hidden', foreground='gray80')

        # Packet details
        self.details_text = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=100, height=15)
        self.details_text.grid(row=3, column=0, columnspan=2, padx=5, pady=5, sticky='nsew')

        # Buttons
        self.button_frame = tk.Frame(self.root)
        self.button_frame.grid(row=4, column=0, columnspan=2, pady=5)

        self.start_button = tk.Button(self.button_frame, text="Start", command=self.analyzer.start_listening)
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = tk.Button(self.button_frame, text="Stop", command=self.analyzer.stop_listening, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        self.clear_button = tk.Button(self.button_frame, text="Clear", command=self.clear_packets)
        self.clear_button.pack(side=tk.LEFT, padx=5)

        # File operations
        self.file_frame = tk.Frame(self.root)
        self.file_frame.grid(row=5, column=0, columnspan=2, pady=5)

        self.save_button = tk.Button(self.file_frame, text="Save Session", command=self.save_session)
        self.save_button.pack(side=tk.LEFT, padx=5)

        self.load_button = tk.Button(self.file_frame, text="Load Session", command=self.load_session)
        self.load_button.pack(side=tk.LEFT, padx=5)

        # Grid configuration
        self.root.grid_rowconfigure(2, weight=1)
        self.root.grid_columnconfigure(1, weight=1)

        # Bindings
        self.packet_tree.bind('<<TreeviewSelect>>', self.show_packet_details)

    def add_packet_to_tree(self, packet_data):
        self.packet_tree.insert('', 'end', values=packet_data[:7], tags=(str(packet_data[0]), packet_data[7]))

    def clear_packets(self):
        self.packet_tree.delete(*self.packet_tree.get_children())
        self.details_text.delete(1.0, tk.END)

    def set_listening_state(self, is_listening):
        self.start_button.config(state=tk.DISABLED if is_listening else tk.NORMAL)
        self.stop_button.config(state=tk.NORMAL if is_listening else tk.DISABLED)
        self.clear_button.config(state=tk.DISABLED if is_listening else tk.NORMAL)

    def show_packet_details(self, event=None):
        selected_item = self.packet_tree.selection()
        if not selected_item:
            return

        item = self.packet_tree.item(selected_item)
        packet = item['tags'][1] if len(item['tags']) > 1 else None

        if not packet:
            return

        self.details_text.delete(1.0, tk.END)
        self.details_text.insert(tk.END, f"Packet #{item['values'][0]} captured at {item['values'][1]}\n")
        self.details_text.insert(tk.END, f"Source: {item['values'][2]}\n")
        self.details_text.insert(tk.END, f"Destination: {item['values'][3]}\n")
        self.details_text.insert(tk.END, f"Protocol: {item['values'][4]}\n")
        self.details_text.insert(tk.END, f"Length: {item['values'][5]} bytes\n\n")
        self.details_text.insert(tk.END, "Hex dump:\n")

        if isinstance(packet, str):
            try:
                packet = packet.encode('latin-1')
            except:
                packet = b''

        for i in range(0, len(packet), 16):
            chunk = packet[i:i+16]
            hex_str = ' '.join(f"{b:02x}" for b in chunk)
            ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            self.details_text.insert(tk.END, f"{i:04x}: {hex_str.ljust(47)}  {ascii_str}\n")

    def apply_filter(self, *args):
        filter_text = self.filter_text.get().lower()
        for item in self.packet_tree.get_children():
            packet_data = self.packet_tree.item(item)
            values = packet_data['values']

            if not filter_text:
                self.packet_tree.item(item, tags=())
                continue

            if (filter_text in str(values[2]).lower() or
                filter_text in str(values[3]).lower() or
                filter_text in str(values[4]).lower() or
                filter_text in str(values[6]).lower()):
                self.packet_tree.item(item, tags=())
            else:
                self.packet_tree.item(item, tags=('hidden',))

    def show_error(self, title, message):
        messagebox.showerror(title, message)

    def get_interface_names(self):
        return [name for name, addrs in psutil.net_if_addrs().items() if self.can_listen(name)]

    def can_listen(self, interface):
        return any(addr.family == socket.AF_INET for addr in psutil.net_if_addrs().get(interface, []))

    def get_interface_ip(self, interface):
        addresses = psutil.net_if_addrs().get(interface, [])
        for addr in addresses:
            if addr.family == socket.AF_INET:
                return addr.address
        return None

    def is_windows(self):
        return platform.system() == "Windows"

    def save_session(self):
        if not self.packet_tree.get_children():
            self.show_error("Warning", "No packets to save")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".psniff",
            filetypes=[("Packet Sniffer files", "*.psniff"), ("All files", "*.*")]
        )

        if not file_path:
            return

        try:
            packets = []
            for item in self.packet_tree.get_children():
                packet_data = self.packet_tree.item(item)
                packets.append({
                    'values': packet_data['values'],
                    'tags': packet_data['tags'],
                    'packet': packet_data['tags'][1] if len(packet_data['tags']) > 1 else None
                })

            with open(file_path, 'wb') as f:
                pickle.dump({
                    'packets': packets,
                    'filter': self.filter_text.get()
                }, f)

            messagebox.showinfo("Success", f"Session saved to {file_path}")
        except Exception as e:
            self.show_error("Error", f"Failed to save session: {str(e)}")

    def load_session(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Packet Sniffer files", "*.psniff"), ("All files", "*.*")]
        )

        if not file_path:
            return

        try:
            with open(file_path, 'rb') as f:
                session = pickle.load(f)

            viewer = tk.Toplevel(self.root)
            viewer.title(f"Packet Sniffer Viewer - {os.path.basename(file_path)}")

            # Filter frame
            filter_var = tk.StringVar(value=session.get('filter', ''))
            filter_frame = tk.Frame(viewer)
            filter_frame.pack(fill=tk.X, padx=5, pady=5)

            tk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT)
            filter_entry = tk.Entry(filter_frame, textvariable=filter_var)
            filter_entry.pack(side=tk.LEFT, expand=True, fill=tk.X)

            # Packet tree
            packet_tree = ttk.Treeview(viewer, columns=self.COLUMNS, show='headings')
            for col in self.COLUMNS:
                packet_tree.heading(col, text=col)
                packet_tree.column(col, width=100)

            packet_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

            # Details text
            details_text = scrolledtext.ScrolledText(viewer, wrap=tk.WORD, width=100, height=15)
            details_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

            # Load packets
            for packet_data in session['packets']:
                packet_tree.insert('', 'end',
                                 values=packet_data['values'],
                                 tags=packet_data['tags'])

            def show_details(event):
                selected_item = packet_tree.selection()
                if not selected_item:
                    return

                item = packet_tree.item(selected_item)
                packet = item['tags'][1] if len(item['tags']) > 1 else None

                if not packet:
                    return

                details_text.delete(1.0, tk.END)
                details_text.insert(tk.END, f"Packet #{item['values'][0]} captured at {item['values'][1]}\n")
                details_text.insert(tk.END, f"Source: {item['values'][2]}\n")
                details_text.insert(tk.END, f"Destination: {item['values'][3]}\n")
                details_text.insert(tk.END, f"Protocol: {item['values'][4]}\n")
                details_text.insert(tk.END, f"Length: {item['values'][5]} bytes\n\n")
                details_text.insert(tk.END, "Hex dump:\n")

                if isinstance(packet, str):
                    try:
                        packet = packet.encode('latin-1')
                    except:
                        packet = b''

                for i in range(0, len(packet), 16):
                    chunk = packet[i:i+16]
                    hex_str = ' '.join(f"{b:02x}" for b in chunk)
                    ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                    details_text.insert(tk.END, f"{i:04x}: {hex_str.ljust(47)}  {ascii_str}\n")

            packet_tree.bind('<<TreeviewSelect>>', show_details)

            def apply_filter(*args):
                filter_text = filter_var.get().lower()
                for item in packet_tree.get_children():
                    packet_data = packet_tree.item(item)
                    values = packet_data['values']
                    tags = packet_data['tags']

                    if not filter_text:
                        packet_tree.item(item, tags=tags)
                        continue

                    if (filter_text in str(values[2]).lower() or
                        filter_text in str(values[3]).lower() or
                        filter_text in str(values[4]).lower() or
                        filter_text in str(values[6]).lower()):
                        packet_tree.item(item, tags=tags)
                    else:
                        packet_tree.item(item, tags=('hidden',))

                packet_tree.tag_configure('hidden', foreground='gray80')

            filter_var.trace_add('write', apply_filter)
            apply_filter()

        except Exception as e:
            self.show_error("Error", f"Failed to load session: {str(e)}")