import socket
import struct

class ProtocolParser:
    def __init__(self):
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

    def parse(self, packet):
        try:
            version = packet[0] >> 4 if len(packet) > 0 else 0

            if version == 4:
                return self._parse_ipv4(packet)
            elif version == 6:
                return self._parse_ipv6(packet)
            else:
                return self._parse_non_ip(packet)
        except Exception as e:
            print(f"Parsing error: {e}")
            return None

    def _parse_ipv4(self, packet):
        ip_header = packet[:20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        protocol = iph[6]
        src_ip = socket.inet_ntoa(iph[8])
        dst_ip = socket.inet_ntoa(iph[9])
        protocol_name = self.ip_proto_names.get(protocol, f"Proto {protocol}")
        src_port, dst_port, info = self._parse_transport(packet, protocol, "IPv4")
        return {
            'version': 'IPv4',
            'src': f"{src_ip}:{src_port}" if src_port else src_ip,
            'dst': f"{dst_ip}:{dst_port}" if dst_port else dst_ip,
            'protocol': protocol_name,
            'info': info,
            'raw': packet
        }

    def _parse_transport(self, packet, protocol, ip_version):
        try:
            if ip_version == "IPv4":
                ip_header_length = (packet[0] & 0xF) * 4
            elif ip_version == "IPv6":
                ip_header_length = 40
            else:
                return None, None, "Unknown"

            transport = packet[ip_header_length:]

            if protocol == 6 and len(transport) >= 20:  # TCP
                tcph = struct.unpack('!HHLLBBHHH', transport[:20])
                return tcph[0], tcph[1], f"TCP Flags: {tcph[5]}"
            elif protocol == 17 and len(transport) >= 8:  # UDP
                udph = struct.unpack('!HHHH', transport[:8])
                return udph[0], udph[1], f"UDP Length: {udph[2]}"
            return None, None, ""
        except Exception as e:
            print(f"Transport parsing error: {e}")
            return None, None, "Error"