import socket
import struct
from datetime import datetime
import platform

class PacketParser:
    def __init__(self):
        self.packet_count = 0

    def get_eth_protocol_name(self, eth_proto):
        eth_proto_names = {
            0x0800: "IPv4",
            0x0806: "ARP",
            0x86DD: "IPv6",
            0x8100: "VLAN",
            0x88CC: "LLDP"
        }
        return eth_proto_names.get(eth_proto, f"0x{eth_proto:04x}")

    def get_protocol_name(self, protocol):
        protocol_names = {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
            2: "IGMP",
            58: "ICMPv6",
            89: "OSPF"
        }
        return protocol_names.get(protocol, f"Proto {protocol}")

    def parse_transport_header(self, packet, protocol, ip_version):
        try:
            if ip_version == "IPv4":
                ip_header_length = (packet[0] & 0xF) * 4
            elif ip_version == "IPv6":
                ip_header_length = 40
            else:
                return None, None, "Unknown transport"

            transport_packet = packet[ip_header_length:]

            if protocol == 6:  # TCP
                if len(transport_packet) >= 20:
                    tcph = struct.unpack('!HHLLBBHHH', transport_packet[:20])
                    return tcph[0], tcph[1], f"TCP Flags: {tcph[5]}"

            elif protocol == 17:  # UDP
                if len(transport_packet) >= 8:
                    udph = struct.unpack('!HHHH', transport_packet[:8])
                    return udph[0], udph[1], f"UDP Length: {udph[2]}"

            elif protocol == 58:  # ICMPv6
                return None, None, "ICMPv6"

        except Exception as e:
            print(f"Error parsing transport header: {e}")
        return None, None, "Unknown transport"

    def parse_ip_header(self, packet):
        try:
            version = packet[0] >> 4

            if version == 4:
                ip_header = packet[:20]
                iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                return iph[6], socket.inet_ntoa(iph[8]), socket.inet_ntoa(iph[9]), "IPv4"

            elif version == 6:
                ip_header = packet[:40]
                iph = struct.unpack('!IHBB16s16s', ip_header[:40])
                return iph[2], socket.inet_ntop(socket.AF_INET6, iph[4]), socket.inet_ntop(socket.AF_INET6, iph[5]), "IPv6"

        except Exception as e:
            print(f"Error parsing IP header: {e}")
        return None, "Unknown", "Unknown", "Unknown"

    def process_packet(self, packet):
        try:
            if isinstance(packet, str):
                try:
                    packet = packet.encode('latin-1')
                except:
                    packet = b''

            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            length = len(packet)

            if platform.system() == "Windows":
                protocol, src_ip, dst_ip, ip_version = self.parse_ip_header(packet)
                if protocol is None:
                    return None

                protocol_name = self.get_protocol_name(protocol)
                src_port, dst_port, info = self.parse_transport_header(packet, protocol, ip_version)

                src = f"{src_ip}:{src_port}" if src_port else src_ip
                dst = f"{dst_ip}:{dst_port}" if dst_port else dst_ip

            else:
                if len(packet) >= 14:
                    eth_header = packet[:14]
                    try:
                        eth_proto = struct.unpack("!H", eth_header[12:14])[0]
                    except:
                        eth_proto = 0

                    if eth_proto in (0x0800, 0x86DD):  # IPv4/IPv6
                        protocol, src_ip, dst_ip, ip_version = self.parse_ip_header(packet[14:])
                        protocol_name = self.get_protocol_name(protocol)
                        src_port, dst_port, info = self.parse_transport_header(packet[14:], protocol, ip_version)

                        src = f"{src_ip}:{src_port}" if src_port else src_ip
                        dst = f"{dst_ip}:{dst_port}" if dst_port else dst_ip
                    else:
                        protocol_name = self.get_eth_protocol_name(eth_proto)
                        src = eth_header[0:6].hex(':') if len(eth_header) >= 12 else "Unknown"
                        dst = eth_header[6:12].hex(':') if len(eth_header) >= 12 else "Unknown"
                        info = f"EtherType: 0x{eth_proto:04x}"

            self.packet_count += 1
            return (self.packet_count, timestamp, src, dst, protocol_name, length, info, packet)

        except Exception as e:
            print(f"Error processing packet: {e}")
            return None