import tkinter as tk
from tkinter import ttk, messagebox
from queue import Queue
from core.capture import PacketCapture
from core.analyzer import PacketAnalyzer
from gui.widgets import PacketTree, DetailsText

class MainWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Analyzer")

        self.packet_queue = Queue()
        self.capture = PacketCapture(self.packet_queue)
        self.analyzer = PacketAnalyzer()  # Инициализация с нужными зависимостями

        self._setup_ui()
        self._setup_bindings()

    def _setup_ui(self):
        # Создание интерфейса
        self.packet_tree = PacketTree(self.root)
        self.details_text = DetailsText(self.root)

        # Кнопки управления
        self.control_frame = tk.Frame(self.root)
        self.start_btn = tk.Button(self.control_frame, text="Start", command=self.start_capture)
        self.stop_btn = tk.Button(self.control_frame, text="Stop", command=self.stop_capture, state=tk.DISABLED)

        # Размещение элементов
        self.packet_tree.grid(row=0, column=0, sticky="nsew")
        self.details_text.grid(row=1, column=0, sticky="nsew")
        self.control_frame.grid(row=2, column=0)
        self.start_btn.pack(side=tk.LEFT)
        self.stop_btn.pack(side=tk.LEFT)

        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

    def start_capture(self):
        interface = self.interface_combo.get()
        if interface:
            self.capture.start(interface)
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.update_ui()

    def update_ui(self):
        # Метод для периодического обновления интерфейса
        pass