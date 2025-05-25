import psutil
import socket
import platform
from typing import List, Optional, Dict
from datetime import datetime

def get_available_interfaces() -> List[Dict[str, str]]:
    """Возвращает список доступных сетевых интерфейсов с их IP-адресами"""
    interfaces = []
    for interface, addrs in psutil.net_if_addrs().items():
        ipv4 = next((addr.address for addr in addrs if addr.family == socket.AF_INET), None)
        if ipv4:
            interfaces.append({
                'name': interface,
                'ip': ipv4,
                'is_loopback': interface.lower() == 'lo' or ipv4.startswith('127.')
            })
    return interfaces

def is_valid_interface(interface_name: str) -> bool:
    """Проверяет, может ли интерфейс использоваться для захвата пакетов"""
    if not interface_name:
        return False

    if platform.system() == "Windows":
        return any(
            iface['name'] == interface_name and not iface['is_loopback']
            for iface in get_available_interfaces()
        )
    else:
        # Для Linux проверяем наличие интерфейса в системе
        return interface_name in psutil.net_if_addrs()

def format_mac_address(raw_mac: bytes) -> str:
    """Форматирует MAC-адрес из байтов в читаемый вид (00:11:22:aa:bb:cc)"""
    return ":".join(f"{byte:02x}" for byte in raw_mac)

def format_timestamp(timestamp: float) -> str:
    """Форматирует временную метку в читаемый формат"""
    return datetime.fromtimestamp(timestamp).strftime("%H:%M:%S.%f")[:-3]

def calculate_checksum(packet: bytes) -> int:
    """Вычисляет контрольную сумму для пакета (упрощённая реализация)"""
    if len(packet) % 2 != 0:
        packet += b'\x00'

    total = 0
    for i in range(0, len(packet), 2):
        word = (packet[i] << 8) + packet[i+1]
        total += word
        total = (total & 0xffff) + (total >> 16)

    return ~total & 0xffff

def get_os_specific_socket() -> socket.socket:
    """Создаёт и возвращает сокет в зависимости от ОС"""
    if platform.system() == "Windows":
        return socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    else:
        return socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

def enable_promiscuous_mode(sock: socket.socket, interface: str) -> bool:
    """Включает promiscuous mode для сокета"""
    try:
        if platform.system() == "Windows":
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        else:
            # Linux требует дополнительных прав и конфигурации
            import fcntl
            import struct
            ifreq = struct.pack('16sH', interface.encode(), socket.PACKET_MR_PROMISC)
            fcntl.ioctl(sock, socket.SIOCGIFFLAGS, ifreq)
        return True
    except Exception as e:
        print(f"Failed to enable promiscuous mode: {e}")
        return False

def packet_to_hexdump(packet: bytes, bytes_per_line: int = 16) -> str:
    """Генерирует hexdump пакета для отображения"""
    hexdump = []
    for i in range(0, len(packet), bytes_per_line):
        chunk = packet[i:i+bytes_per_line]
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        hexdump.append(f"{i:04x}: {hex_str.ljust(3*bytes_per_line)}  {ascii_str}")
    return "\n".join(hexdump)

def validate_ip_address(ip: str) -> bool:
    """Проверяет валидность IPv4 или IPv6 адреса"""
    try:
        socket.inet_pton(socket.AF_INET6 if ":" in ip else socket.AF_INET, ip)
        return True
    except socket.error:
        return False