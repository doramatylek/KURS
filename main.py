from packet_analyzer.analyzer import PacketAnalyzer
import tkinter as tk

if __name__ == "__main__":
    root = tk.Tk()
    analyzer = PacketAnalyzer(root)
    root.mainloop()