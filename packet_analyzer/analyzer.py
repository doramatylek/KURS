import socket
import threading
from queue import Queue
from .packet_parser import PacketParser
from .gui import GUIManager

class PacketAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Raw Socket Packet Analyzer")
        
        # Variables
        self.is_listening = False
        self.socket = None
        self.packet_queue = Queue()
        self.batch_size = 50
        self.max_packets = 10000
        
        # Components
        self.parser = PacketParser()
        self.gui = GUIManager(root, self)
    
    def capture_packets(self):
        while self.is_listening:
            try:
                packet, _ = self.socket.recvfrom(65535)
                self.packet_queue.put(packet)
            except socket.timeout:
                continue
            except Exception as e:
                if self.is_listening:
                    self.root.after(0, lambda: self.gui.show_error("Error", f"Capture error: {str(e)}"))
                break

    def update_ui(self):
        packets_to_process = []
        while len(packets_to_process) < self.batch_size and not self.packet_queue.empty():
            packet = self.packet_queue.get()
            packets_to_process.append(packet)
        
        if packets_to_process:
            if len(self.gui.packet_tree.get_children()) + len(packets_to_process) > self.max_packets:
                items_to_remove = len(self.gui.packet_tree.get_children()) + len(packets_to_process) - self.max_packets
                for item in list(self.gui.packet_tree.get_children())[:items_to_remove]:
                    self.gui.packet_tree.delete(item)
            
            self.gui.packet_tree.configure(displaycolumns=[])
            
            for packet in packets_to_process:
                processed = self.parser.process_packet(packet)
                if processed:
                    self.gui.add_packet_to_tree(processed)
            
            self.gui.packet_tree.configure(displaycolumns=self.gui.COLUMNS)
            self.gui.packet_tree.see(self.gui.packet_tree.get_children()[-1])
        
        self.root.after(100, self.update_ui)

    def start_listening(self):
        selected_interface = self.gui.interface_combo.get()
        if not selected_interface:
            self.gui.show_error("Error", "Please select an interface")
            return

        self.is_listening = True
        self.gui.set_listening_state(True)
        
        ip_address = self.gui.get_interface_ip(selected_interface)
        if not ip_address:
            self.gui.show_error("Error", "Invalid IP address for the selected interface")
            self.stop_listening()
            return

        try:
            if self.gui.is_windows():
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                self.socket.bind((ip_address, 0))
                self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
                self.socket.bind((selected_interface, 0))
            
            self.socket.settimeout(1.0)
            threading.Thread(target=self.capture_packets, daemon=True).start()
            self.update_ui()
        except Exception as e:
            self.gui.show_error("Error", f"Failed to start capture: {str(e)}")
            self.stop_listening()

    def stop_listening(self):
        self.is_listening = False
        self.gui.set_listening_state(False)
        
        if self.socket:
            try:
                if self.gui.is_windows():
                    self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                self.socket.close()
            except:
                pass
            self.socket = None