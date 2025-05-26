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
        self.current_packet_details = None

    def setup_ui(self):
        # Main container
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Top panel (controls)
        self.control_frame = ttk.Frame(self.main_frame)
        self.control_frame.pack(fill=tk.X, pady=(0, 5))

        # Interface selection
        self.interface_label = ttk.Label(self.control_frame, text="Interface:")
        self.interface_label.pack(side=tk.LEFT, padx=(0, 5))

        self.interface_combo = ttk.Combobox(self.control_frame, values=self.get_interface_names(), width=25)
        self.interface_combo.pack(side=tk.LEFT, padx=(0, 10))

        # Filter setup
        self.filter_label = ttk.Label(self.control_frame, text="Filter:")
        self.filter_label.pack(side=tk.LEFT, padx=(0, 5))

        self.filter_text = tk.StringVar()
        self.filter_entry = ttk.Entry(self.control_frame, textvariable=self.filter_text, width=30)
        self.filter_entry.pack(side=tk.LEFT, padx=(0, 10))
        self.filter_text.trace_add('write', self.apply_filter)

        # Buttons
        self.start_button = ttk.Button(self.control_frame, text="Start", command=self.analyzer.start_listening)
        self.start_button.pack(side=tk.LEFT, padx=(0, 5))

        self.stop_button = ttk.Button(self.control_frame, text="Stop", command=self.analyzer.stop_listening, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=(0, 5))

        self.clear_button = ttk.Button(self.control_frame, text="Clear", command=self.clear_packets)
        self.clear_button.pack(side=tk.LEFT, padx=(0, 5))

        # Packet display area
        self.packet_panel = ttk.PanedWindow(self.main_frame, orient=tk.VERTICAL)
        self.packet_panel.pack(fill=tk.BOTH, expand=True)

        # Packet list (treeview)
        self.packet_tree_frame = ttk.Frame(self.packet_panel)
        self.packet_tree = ttk.Treeview(self.packet_tree_frame, columns=self.COLUMNS, show='headings', selectmode='browse')

        # Configure columns
        col_widths = {
            'No': 50, 'Time': 120, 'Source': 180,
            'Destination': 180, 'Protocol': 80,
            'Length': 70, 'Info': 300
        }

        for col in self.COLUMNS:
            self.packet_tree.heading(col, text=col)
            self.packet_tree.column(col, width=col_widths.get(col, 100))

        # Add scrollbars
        tree_scroll_y = ttk.Scrollbar(self.packet_tree_frame, orient=tk.VERTICAL, command=self.packet_tree.yview)
        tree_scroll_x = ttk.Scrollbar(self.packet_tree_frame, orient=tk.HORIZONTAL, command=self.packet_tree.xview)
        self.packet_tree.configure(yscrollcommand=tree_scroll_y.set, xscrollcommand=tree_scroll_x.set)

        # Grid layout for treeview and scrollbars
        self.packet_tree.grid(row=0, column=0, sticky='nsew')
        tree_scroll_y.grid(row=0, column=1, sticky='ns')
        tree_scroll_x.grid(row=1, column=0, sticky='ew')

        self.packet_tree_frame.grid_rowconfigure(0, weight=1)
        self.packet_tree_frame.grid_columnconfigure(0, weight=1)

        self.packet_panel.add(self.packet_tree_frame, weight=1)

        # Packet details (treeview for layers)
        self.details_frame = ttk.Frame(self.packet_panel)
        self.details_tree = ttk.Treeview(self.details_frame, columns=('field', 'value', 'bytes'), show='tree', selectmode='browse')
        self.details_tree.heading('#0', text='Packet Layers')
        self.details_tree.heading('field', text='Field')
        self.details_tree.heading('value', text='Value')
        self.details_tree.heading('bytes', text='Bytes')

        self.details_tree.column('#0', width=150)
        self.details_tree.column('field', width=150)
        self.details_tree.column('value', width=250)
        self.details_tree.column('bytes', width=150)

        # Add scrollbars
        details_scroll_y = ttk.Scrollbar(self.details_frame, orient=tk.VERTICAL, command=self.details_tree.yview)
        details_scroll_x = ttk.Scrollbar(self.details_frame, orient=tk.HORIZONTAL, command=self.details_tree.xview)
        self.details_tree.configure(yscrollcommand=details_scroll_y.set, xscrollcommand=details_scroll_x.set)

        # Grid layout for details tree
        self.details_tree.grid(row=0, column=0, sticky='nsew')
        details_scroll_y.grid(row=0, column=1, sticky='ns')
        details_scroll_x.grid(row=1, column=0, sticky='ew')

        self.details_frame.grid_rowconfigure(0, weight=1)
        self.details_frame.grid_columnconfigure(0, weight=1)

        self.packet_panel.add(self.details_frame, weight=1)

        # Hex dump panel
        self.hex_frame = ttk.Frame(self.main_frame)
        self.hex_frame.pack(fill=tk.BOTH, expand=False, pady=(5, 0))

        self.hex_text = scrolledtext.ScrolledText(self.hex_frame, wrap=tk.WORD, width=100, height=10)
        self.hex_text.pack(fill=tk.BOTH, expand=True)

        # Status bar
        self.status_var = tk.StringVar()
        self.status_bar = ttk.Label(self.main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        self.status_bar.pack(fill=tk.X, pady=(5, 0))

        # Bindings
        self.packet_tree.bind('<<TreeviewSelect>>', self.show_packet_details)
        self.details_tree.bind('<<TreeviewSelect>>', self.show_hex_for_field)

        # Initialize
        self.update_status()

    def add_packet_to_tree(self, packet_data):
        values = (
            len(self.packet_tree.get_children()) + 1,
            packet_data['timestamp'],
            f"{packet_data.get('src_ip', '')}:{packet_data.get('src_port', '')}",
            f"{packet_data.get('dst_ip', '')}:{packet_data.get('dst_port', '')}",
            packet_data.get('protocol', ''),
            packet_data['length'],
            packet_data.get('info', '')
        )
        self.packet_tree.insert('', 'end', values=values)

    def clear_packets(self):
        """Clear all captured packets"""
        self.packet_tree.delete(*self.packet_tree.get_children())
        self.clear_details()
        self.update_status()

    def clear_details(self):
        """Clear packet details view"""
        self.details_tree.delete(*self.details_tree.get_children())
        self.hex_text.delete(1.0, tk.END)
        self.current_packet_details = None

    def set_listening_state(self, is_listening):
        """Update UI controls based on capture state"""
        self.start_button.config(state=tk.DISABLED if is_listening else tk.NORMAL)
        self.stop_button.config(state=tk.NORMAL if is_listening else tk.DISABLED)
        self.clear_button.config(state=tk.DISABLED if is_listening else tk.NORMAL)
        self.interface_combo.config(state=tk.DISABLED if is_listening else tk.NORMAL)

    def show_packet_details(self, event=None):
        """Show detailed view of selected packet"""
        selected_item = self.packet_tree.selection()
        if not selected_item:
            return

        # Clear previous details
        self.clear_details()

        # Get the packet data from analyzer
        item_index = self.packet_tree.index(selected_item[0])
        packet_data = self.analyzer.get_packet_data(item_index)

        if not packet_data or 'layers' not in packet_data:
            return

        self.current_packet_details = packet_data

        # Add layers to details tree
        for layer_name, layer_data in packet_data['layers'].items():
            layer_node = self.details_tree.insert('', 'end', text=layer_name, open=True)

            if 'fields' in layer_data:
                for field in layer_data['fields']:
                    field_node = self.details_tree.insert(layer_node, 'end',text=field['name'],values=(field['value'], field.get('bytes', b'').hex(' ') if 'bytes' in field else ''))
        # Show hex dump of entire packet
        self.show_hex_dump(packet_data['raw'])

    def show_hex_for_field(self, event=None):
        """Show hex dump for selected field in details tree"""
        if not self.current_packet_details:
            return

        selected_item = self.details_tree.selection()
        if not selected_item:
            return

        item = self.details_tree.item(selected_item[0])
        if 'bytes' in item['values'] and item['values'][1]:
            self.show_hex_dump(bytes.fromhex(item['values'][1].replace(' ', '')))

    def show_hex_dump(self, data):
        """Display hex dump of binary data"""
        self.hex_text.delete(1.0, tk.END)

        if not data:
            return

        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_str = ' '.join(f"{b:02x}" for b in chunk)
            ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            self.hex_text.insert(tk.END, f"{i:04x}: {hex_str.ljust(47)}  {ascii_str}\n")

    def apply_filter(self, *args):
        """Apply filter to packet list"""
        filter_text = self.filter_text.get().lower()
        for item in self.packet_tree.get_children():
            values = self.packet_tree.item(item)['values']

            if not filter_text:
                self.packet_tree.item(item, tags=())
                continue

            if (filter_text in str(values[1]).lower() or  # Time
                filter_text in str(values[2]).lower() or  # Source
                filter_text in str(values[3]).lower() or  # Destination
                filter_text in str(values[4]).lower() or  # Protocol
                filter_text in str(values[6]).lower()):   # Info
                self.packet_tree.item(item, tags=())
            else:
                self.packet_tree.item(item, tags=('hidden',))

        self.packet_tree.tag_configure('hidden', foreground='gray80')

    def update_status(self):
        """Update status bar with packet count"""
        count = len(self.packet_tree.get_children())
        self.status_var.set(f"Packets: {count}")

    def show_error(self, title, message):
        """Show error message dialog"""
        messagebox.showerror(title, message)

    def get_interface_names(self):
        """Get list of available network interfaces"""
        return [name for name, addrs in psutil.net_if_addrs().items() if self.can_listen(name)]

    def can_listen(self, interface):
        """Check if interface can be used for listening"""
        return any(addr.family == socket.AF_INET for addr in psutil.net_if_addrs().get(interface, []))

    def get_interface_ip(self, interface):
        """Get IP address for specified interface"""
        addresses = psutil.net_if_addrs().get(interface, [])
        for addr in addresses:
            if addr.family == socket.AF_INET:
                return addr.address
        return None

    def is_windows(self):
        """Check if running on Windows"""
        return platform.system() == "Windows"