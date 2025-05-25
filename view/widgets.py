from tkinter import ttk, scrolledtext

class PacketTree(ttk.Treeview):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self._setup_columns()

    def _setup_columns(self):
        self["columns"] = ("No", "Time", "Source", "Destination", "Protocol", "Length", "Info")
        for col in self["columns"]:
            self.heading(col, text=col)

class DetailsText(scrolledtext.ScrolledText):
    def __init__(self, master, **kwargs):
        super().__init__(master, wrap=tk.WORD, **kwargs)
        self.config(state=tk.DISABLED)