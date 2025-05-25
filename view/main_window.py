from queue import Queue
from tkinter import ttk, scrolledtext, messagebox
import tkinter as tk
from datetime import datetime

class MainWindow:
    def __init__(self, root, analyzer):
        self.root = root
        self.analyzer = analyzer
        self.packet_queue = Queue()
        self.packet_count = 0
        self._setup_ui()
        self._setup_bindings()
    
    def _setup_ui(self):
        """Инициализация интерфейса"""
        self.root.title("Packet Analyzer")
        self.root.geometry("1000x800")
        
        # Main frame
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Treeview для пакетов
        self.packet_tree = ttk.Treeview(main_frame, 
                                      columns=('No', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info'),
                                      show='headings',
                                      selectmode='browse')
        
        # Настройка колонок
        columns = {
            'No': {'width': 50, 'anchor': 'center'},
            'Time': {'width': 120},
            'Source': {'width': 150},
            'Destination': {'width': 150},
            'Protocol': {'width': 80},
            'Length': {'width': 60, 'anchor': 'center'},
            'Info': {'width': 300}
        }
        
        for col, params in columns.items():
            self.packet_tree.heading(col, text=col)
            self.packet_tree.column(col, **params)
        
        self.packet_tree.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=self.packet_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.packet_tree.configure(yscrollcommand=scrollbar.set)
        
        # Текстовое поле для деталей
        self.details_text = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD)
        self.details_text.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True)
        
        # Кнопки управления
        button_frame = tk.Frame(self.root)
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Button(button_frame, text="Start", command=self.start_capture).pack(side=tk.LEFT)
        tk.Button(button_frame, text="Stop", command=self.stop_capture).pack(side=tk.LEFT)
        tk.Button(button_frame, text="Clear", command=self.clear_packets).pack(side=tk.LEFT)
    
    def _setup_bindings(self):
        """Настройка обработчиков событий"""
        self.packet_tree.bind('<<TreeviewSelect>>', self._show_packet_details)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def _show_packet_details(self, event):
        """Отображение деталей выбранного пакета"""
        selected_item = self.packet_tree.selection()
        if not selected_item:
            return
        
        item = self.packet_tree.item(selected_item)
        packet_data = item['values']
        raw_packet = item['tags'][0] if item['tags'] else b''
        
        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete(1.0, tk.END)
        
        # Основная информация
        self.details_text.insert(tk.END, f"Packet #{packet_data[0]}\n")
        self.details_text.insert(tk.END, f"Timestamp: {packet_data[1]}\n")
        self.details_text.insert(tk.END, f"Source: {packet_data[2]}\n")
        self.details_text.insert(tk.END, f"Destination: {packet_data[3]}\n")
        self.details_text.insert(tk.END, f"Protocol: {packet_data[4]}\n")
        self.details_text.insert(tk.END, f"Length: {packet_data[5]} bytes\n\n")
        
        # Hex dump
        self.details_text.insert(tk.END, "Hex dump:\n")
        
        if isinstance(raw_packet, str):
            try:
                raw_packet = raw_packet.encode('latin-1')
            except:
                raw_packet = b''
        
        for i in range(0, len(raw_packet), 16):
            chunk = raw_packet[i:i+16]
            hex_str = ' '.join(f"{b:02x}" for b in chunk)
            ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            self.details_text.insert(tk.END, f"{i:04x}: {hex_str.ljust(47)}  {ascii_str}\n")
        
        self.details_text.config(state=tk.DISABLED)
    
    def start_capture(self):
        """Начать захват пакетов"""
        self.packet_count = 0
        messagebox.showinfo("Info", "Capture started")
    
    def stop_capture(self):
        """Остановить захват пакетов"""
        messagebox.showinfo("Info", "Capture stopped")
    
    def clear_packets(self):
        """Очистить список пакетов"""
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)
        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete(1.0, tk.END)
        self.details_text.config(state=tk.DISABLED)
        self.packet_count = 0
    
    def on_close(self):
        """Обработчик закрытия окна"""
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.root.destroy()
    
    def add_packet(self, packet_data):
        """Добавить пакет в Treeview"""
        self.packet_count += 1
        values = (
            self.packet_count,
            datetime.now().strftime("%H:%M:%S.%f")[:-3],
            packet_data.get('src', 'Unknown'),
            packet_data.get('dst', 'Unknown'),
            packet_data.get('protocol', 'Unknown'),
            len(packet_data.get('raw', b'')),
            packet_data.get('info', '')
        )
        self.packet_tree.insert('', 'end', values=values, tags=(packet_data.get('raw', b''),))
        self.packet_tree.see(self.packet_tree.get_children()[-1])