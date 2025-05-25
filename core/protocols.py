import socket
import struct
from typing import Optional, Tuple, Dict

class ProtocolParser:
    def __init__(self):
        # Словари для преобразования числовых идентификаторов в имена протоколов
        self.eth_proto_names = {
            0x0800: "IPv4",
            0x0806: "ARP",
            0x86DD: "IPv6",
            0x8100: "VLAN",
            0x88CC: "LLDP"
        }

        self.ip_proto_names = {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
            2: "IGMP",
            58: "ICMPv6",
            89: "OSPF"
        }

    def parse(self, packet: bytes) -> Optional[Dict]:
        """Основной метод для разбора сетевого пакета"""
        try:
            if not packet:
                return None

            # Определяем версию IP (первые 4 бита)
            version = packet[0] >> 4 if len(packet) > 0 else 0

            if version == 4:
                return self._parse_ipv4_packet(packet)
            elif version == 6:
                return self._parse_ipv6_packet(packet)
            else:
                return self._parse_non_ip_packet(packet)

        except Exception as e:
            print(f"Error parsing packet: {e}")
            return None

    def _parse_ipv4_packet(self, packet: bytes) -> Dict:
        """Разбор IPv4 пакета"""
        ip_header = packet[:20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

        protocol = iph[6]
        src_ip = socket.inet_ntoa(iph[8])
        dst_ip = socket.inet_ntoa(iph[9])
        protocol_name = self.ip_proto_names.get(protocol, f"Proto {protocol}")

        # Разбор транспортного уровня
        src_port, dst_port, info = self._parse_transport_header(
            packet, protocol, "IPv4"
        )

        return {
            'version': 'IPv4',
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': protocol_name,
            'src_port': src_port,
            'dst_port': dst_port,
            'info': info,
            'raw': packet
        }

    def _parse_ipv6_packet(self, packet: bytes) -> Dict:
        """Разбор IPv6 пакета"""
        ip_header = packet[:40]
        iph = struct.unpack('!IHBB16s16s', ip_header)

        protocol = iph[2]
        src_ip = socket.inet_ntop(socket.AF_INET6, iph[4])
        dst_ip = socket.inet_ntop(socket.AF_INET6, iph[5])
        protocol_name = self.ip_proto_names.get(protocol, f"Proto {protocol}")

        # Разбор транспортного уровня
        src_port, dst_port, info = self._parse_transport_header(
            packet, protocol, "IPv6"
        )

        return {
            'version': 'IPv6',
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': protocol_name,
            'src_port': src_port,
            'dst_port': dst_port,
            'info': info,
            'raw': packet
        }

    def _parse_non_ip_packet(self, packet: bytes) -> Dict:
        """Разбор не-IP пакетов (Ethernet и др.)"""
        if len(packet) < 14:
            return {
                'version': 'Unknown',
                'src': 'Unknown',
                'dst': 'Unknown',
                'protocol': 'Malformed',
                'info': 'Packet too short',
                'raw': packet
            }

        eth_header = packet[:14]
        try:
            eth_proto = struct.unpack("!H", eth_header[12:14])[0]
        except:
            eth_proto = 0

        protocol_name = self.eth_proto_names.get(eth_proto, f"0x{eth_proto:04x}")

        try:
            src = eth_header[0:6].hex(':')
            dst = eth_header[6:12].hex(':')
        except:
            src = "Unknown"
            dst = "Unknown"

        return {
            'version': 'Ethernet',
            'src': src,
            'dst': dst,
            'protocol': protocol_name,
            'info': f"EtherType: 0x{eth_proto:04x}",
            'raw': packet
        }

    def _parse_transport_header(self, packet: bytes, protocol: int, ip_version: str) -> Tuple:
        """Разбор заголовков транспортного уровня (TCP/UDP)"""
        try:
            if ip_version == "IPv4":
                ip_header_length = (packet[0] & 0xF) * 4
            elif ip_version == "IPv6":
                ip_header_length = 40
            else:
                return None, None, "Unknown transport"

            transport_packet = packet[ip_header_length:]

            if protocol == 6 and len(transport_packet) >= 20:  # TCP
                tcph = struct.unpack('!HHLLBBHHH', transport_packet[:20])
                flags = self._parse_tcp_flags(tcph[5])
                return tcph[0], tcph[1], f"TCP Flags: {flags}"

            elif protocol == 17 and len(transport_packet) >= 8:  # UDP
                udph = struct.unpack('!HHHH', transport_packet[:8])
                return udph[0], udph[1], f"UDP Length: {udph[2]}"

            elif protocol == 1:  # ICMP
                return None, None, "ICMP"

            elif protocol == 58:  # ICMPv6
                return None, None, "ICMPv6"

        except Exception as e:
            print(f"Error parsing transport header: {e}")

        return None, None, "Unknown transport"

    def _parse_tcp_flags(self, flags_byte: int) -> str:
        """Разбор TCP флагов"""
        flags = []
        if flags_byte & 0x01: flags.append("FIN")
        if flags_byte & 0x02: flags.append("SYN")
        if flags_byte & 0x04: flags.append("RST")
        if flags_byte & 0x08: flags.append("PSH")
        if flags_byte & 0x10: flags.append("ACK")
        if flags_byte & 0x20: flags.append("URG")
        if flags_byte & 0x40: flags.append("ECE")
        if flags_byte & 0x80: flags.append("CWR")
        return ", ".join(flags) if flags else "None"