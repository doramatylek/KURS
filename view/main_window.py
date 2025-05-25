import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from queue import Queue
import pickle
import os
from datetime import datetime

class MainWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Analyzer")
        
        self.packet_queue = Queue()
        self.packet_count = 0
        self.is_listening = False
        
        self._setup_ui()
        self._setup_bindings()
    
    def _setup_ui(self):
        # Основные элементы интерфейса
        self._create_interface_selector()
        self._create_packet_list()
        self._create_details_view()
        self._create_control_buttons()
    
    def _create_interface_selector(self):
        frame = tk.Frame(self.root)
        frame.pack(fill=tk.X)
        
        tk.Label(frame, text="Interface:").pack(side=tk.LEFT)
        self.interface_combo = ttk.Combobox(frame)
        self.interface_combo.pack(side=tk.LEFT, expand=True, fill=tk.X)
        
        tk.Label(frame, text="Filter:").pack(side=tk.LEFT)
        self.filter_entry = tk.Entry(frame)
        self.filter_entry.pack(side=tk.LEFT, expand=True, fill=tk.X)
    
    def _create_packet_list(self):
        frame = tk.Frame(self.root)
        frame.pack(fill=tk.BOTH, expand=True)
        
        columns = ('No', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info')
        self.packet_tree = ttk.Treeview(frame, columns=columns, show='headings')
        
        for col in columns:
            self.packet_tree.heading(col, text=col)
            self.packet_tree.column(col, width=100)
        
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.packet_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.packet_tree.configure(yscrollcommand=scrollbar.set)
        self.packet_tree.pack(fill=tk.BOTH, expand=True)
    
    def _create_details_view(self):
        self.details_text = scrolledtext.ScrolledText(self.root, wrap=tk.WORD)
        self.details_text.pack(fill=tk.BOTH, expand=True)
    
    def _create_control_buttons(self):
        frame = tk.Frame(self.root)
        frame.pack(fill=tk.X)
        
        tk.Button(frame, text="Start", command=self.start_capture).pack(side=tk.LEFT)
        tk.Button(frame, text="Stop", command=self.stop_capture).pack(side=tk.LEFT)
        tk.Button(frame, text="Clear", command=self.clear_packets).pack(side=tk.LEFT)
        tk.Button(frame, text="Save", command=self.save_session).pack(side=tk.LEFT)
        tk.Button(frame, text="Load", command=self.load_session).pack(side=tk.LEFT)
    
    def start_capture(self):
        selected_interface = self.interface_combo.get()
        if not selected_interface:
            messagebox.showerror("Error", "Please select an interface")
            return

        self.is_listening = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.clear_button.config(state=tk.DISABLED)

        ip_address = self.get_interface_ip(selected_interface)
        if not ip_address:
            messagebox.showerror("Error", "Invalid IP address for the selected interface")
            self.stop_listening()
            return

        try:
            if platform.system() == "Windows":
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                self.socket.bind((ip_address, 0))
                self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
                self.socket.bind((selected_interface, 0))

            self.socket.settimeout(1.0)
            threading.Thread(target=self.capture_packets, daemon=True).start()
            self.update_ui()  # Запускаем обновление интерфейса
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start capture: {str(e)}")
            self.stop_listening()

    def stop_capture(self):
         self.is_listening = False
                self.start_button.config(state=tk.NORMAL)
                self.stop_button.config(state=tk.DISABLED)
                self.clear_button.config(state=tk.NORMAL)

                if self.socket:
                    try:
                        if platform.system() == "Windows":
                            self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                        self.socket.close()
                    except:
                        pass
                    self.socket = None

    
    def clear_packets(self):
        self.packet_tree.delete(*self.packet_tree.get_children())
        self.details_text.delete(1.0, tk.END)
        self.packet_count = 0
    
    def save_session(self):
        if not self.packet_tree.get_children():
            messagebox.showwarning("Warning", "No packets to save")
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
            messagebox.showerror("Error", f"Failed to save session: {str(e)}")

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
            filter_var = StringVar(value=session.get('filter', ''))
            filter_frame = tk.Frame(viewer)
            filter_frame.pack(fill=tk.X, padx=5, pady=5)

            tk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT)
            filter_entry = tk.Entry(filter_frame, textvariable=filter_var)
            filter_entry.pack(side=tk.LEFT, expand=True, fill=tk.X)

            # Packet tree
            columns = ('No', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info')
            packet_tree = ttk.Treeview(viewer, columns=columns, show='headings')
            for col in columns:
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

            # Show details function
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

            # Filter function
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
            messagebox.showerror("Error", f"Failed to load session: {str(e)}")

    def _setup_bindings(self):
        self.packet_tree.bind('<<TreeviewSelect>>', self._show_packet_details)
    
    def _show_packet_details(self, event):
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
