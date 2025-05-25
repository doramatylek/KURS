import socket
import threading
import platform
import psutil

class PacketCapture:
    def __init__(self, packet_handler):
        self.packet_handler = packet_handler
        self.is_listening = False
        self.socket = None

    def start(self, interface):
        self.is_listening = True
        ip_address = self._get_interface_ip(interface)

        if platform.system() == "Windows":
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            self.socket.bind((ip_address, 0))
            self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        else:
            self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            self.socket.bind((interface, 0))

        self.socket.settimeout(1.0)
        threading.Thread(target=self._capture_loop, daemon=True).start()

    def _capture_loop(self):
        while self.is_listening:
            try:
                packet, _ = self.socket.recvfrom(65535)
                self.packet_handler(packet)
            except socket.timeout:
                continue
            except Exception as e:
                if self.is_listening:
                    print(f"Capture error: {e}")
                break

    def stop(self):
        self.is_listening = False
        if self.socket:
            if platform.system() == "Windows":
                self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            self.socket.close()

    def _get_interface_ip(self, interface):
        addrs = psutil.net_if_addrs().get(interface, [])
        return next((addr.address for addr in addrs if addr.family == socket.AF_INET), None)