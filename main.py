import tkinter as tk
from core.protocols import ProtocolParser
from core.analyzer import PacketAnalyzer
from view.main_window import MainWindow

if __name__ == "__main__":
    root = tk.Tk()

    # Создаем необходимые зависимости
    protocol_parser = ProtocolParser()
    packet_analyzer = PacketAnalyzer(protocol_parser)

    # Передаем анализатор в главное окно
    app = MainWindow(root, packet_analyzer)
    root.mainloop()