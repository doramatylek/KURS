import psutil
import socket

def get_available_interfaces():
    interfaces = []
    for name, addrs in psutil.net_if_addrs().items():
        if any(addr.family == socket.AF_INET for addr in addrs):
            interfaces.append(name)
    return interfaces