import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from typing import Dict, List
import pickle
import os
from models.packet import Packet

class ViewerWindow(tk.Toplevel):
    def __init__(self, parent, session_data: Dict = None, file_path: str = None):
        """
        Окно для просмотра сохраненных сессий захвата пакетов

        :param parent: Родительское окно
        :param session_data: Данные сессии (если загружаем напрямую)
        :param file_path: Путь к файлу сессии (если загружаем из файла)
        """
        super().__init__(parent)
        self.title("Packet Sniffer Viewer" + (f" - {os.path.basename(file_path)}" if file_path else ""))

        self.session_data = session_data
        self.file_path = file_path
        self.filter_var = tk.StringVar()

        self._setup_ui()
        self._load_session()

    def _setup_ui(self):
        """Настройка интерфейса окна просмотра"""
        self.geometry("900x700")

        # Frame для фильтров
        filter_frame = tk.Frame(self)
        filter_frame.pack(fill=tk.X, padx=5, pady=5)

        tk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT)
        filter_entry = tk.Entry(filter_frame, textvariable=self.filter_var)
        filter_entry.pack(side=tk.LEFT, expand=True, fill=tk.X)
        filter_entry.bind('<KeyRelease>', self._apply_filter)

        # Кнопки управления
        button_frame = tk.Frame(self)
        button_frame.pack(fill=tk.X, padx=5, pady=5)

        tk.Button(button_frame, text="Export to PCAP", command=self._export_to_pcap).pack(side=tk.LEFT)
        tk.Button(button_frame, text="Close", command=self.destroy).pack(side=tk.RIGHT)

        # Treeview для отображения пакетов
        self.packet_tree = ttk.Treeview(self, columns=('No', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info'),
                                      show='headings', selectmode='browse')

        # Настройка колонок
        self.packet_tree.heading('No', text='No')
        self.packet_tree.heading('Time', text='Time')
        self.packet_tree.heading('Source', text='Source')
        self.packet_tree.heading('Destination', text='Destination')
        self.packet_tree.heading('Protocol', text='Protocol')
        self.packet_tree.heading('Length', text='Length')
        self.packet_tree.heading('Info', text='Info')

        self.packet_tree.column('No', width=50, anchor='center')
        self.packet_tree.column('Time', width=120)
        self.packet_tree.column('Source', width=150)
        self.packet_tree.column('Destination', width=150)
        self.packet_tree.column('Protocol', width=80)
        self.packet_tree.column('Length', width=60, anchor='center')
        self.packet_tree.column('Info', width=300)

        self.packet_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Детали пакета
        self.details_text = scrolledtext.ScrolledText(self, wrap=tk.WORD, width=100, height=15)
        self.details_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Привязка событий
        self.packet_tree.bind('<<TreeviewSelect>>', self._show_packet_details)

    def _load_session(self):
        """Загрузка данных сессии"""
        try:
            if self.file_path and not self.session_data:
                with open(self.file_path, 'rb') as f:
                    self.session_data = pickle.load(f)

            if not self.session_data:
                messagebox.showerror("Error", "No session data to load")
                self.destroy()
                return

            # Заполняем treeview пакетами
            for packet_data in self.session_data.get('packets', []):
                values = packet_data['values']
                self.packet_tree.insert('', 'end',
                                     values=values,
                                     tags=(values[0], packet_data.get('packet', '')))

            # Применяем фильтр если он был в сессии
            if 'filter' in self.session_data:
                self.filter_var.set(self.session_data['filter'])
                self._apply_filter()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to load session: {str(e)}")
            self.destroy()

    def _apply_filter(self, event=None):
        """Применение фильтра к списку пакетов"""
        filter_text = self.filter_var.get().lower()

        for item in self.packet_tree.get_children():
            values = self.packet_tree.item(item)['values']
            tags = self.packet_tree.item(item)['tags']

            if not filter_text:
                self.packet_tree.item(item, tags=tags)
                continue

            # Проверяем соответствие фильтру
            if (filter_text in str(values[2]).lower() or  # Source
                filter_text in str(values[3]).lower() or  # Destination
                filter_text in str(values[4]).lower() or  # Protocol
                filter_text in str(values[6]).lower()):   # Info
                self.packet_tree.item(item, tags=tags)
            else:
                self.packet_tree.item(item, tags=('hidden',))

        self.packet_tree.tag_configure('hidden', foreground='gray80')

    def _show_packet_details(self, event):
        """Отображение деталей выбранного пакета"""
        selected_item = self.packet_tree.selection()
        if not selected_item:
            return

        item = self.packet_tree.item(selected_item)
        packet = item['tags'][1] if len(item['tags']) > 1 else None

        if not packet:
            return

        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete(1.0, tk.END)

        # Основная информация
        self.details_text.insert(tk.END, f"Packet #{item['values'][0]} captured at {item['values'][1]}\n")
        self.details_text.insert(tk.END, f"Source: {item['values'][2]}\n")
        self.details_text.insert(tk.END, f"Destination: {item['values'][3]}\n")
        self.details_text.insert(tk.END, f"Protocol: {item['values'][4]}\n")
        self.details_text.insert(tk.END, f"Length: {item['values'][5]} bytes\n\n")

        # Hex dump
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

        self.details_text.config(state=tk.DISABLED)

    def _export_to_pcap(self):
        """Экспорт сессии в формат PCAP (заглушка)"""
        # В реальной реализации здесь должна быть конвертация в PCAP
        messagebox.showinfo("Info", "PCAP export will be implemented in future version")

    @classmethod
    def from_file(cls, parent):
        """Создание окна просмотра с выбором файла сессии"""
        file_path = filedialog.askopenfilename(
            filetypes=[("Packet Sniffer files", "*.psniff"), ("All files", "*.*")]
        )

        if file_path:
            return cls(parent, file_path=file_path)
        return None