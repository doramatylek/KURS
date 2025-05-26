import socket
import struct
from datetime import datetime
import platform
import dpkt
from collections import defaultdict

class PacketParser:
    def __init__(self):
        self.packet_count = 0
        self.protocol_stats = defaultdict(int)
        self.connection_stats = defaultdict(int)

    def get_eth_protocol_name(self, eth_proto):
        eth_proto_names = {
            0x0800: "IPv4",
            0x0806: "ARP",
            0x86DD: "IPv6",
            0x8100: "VLAN",
            0x88CC: "LLDP",
            0x0805: "X.25",
            0x8035: "RARP"
        }
        return eth_proto_names.get(eth_proto, f"0x{eth_proto:04x}")

    def get_protocol_name(self, protocol):
        protocol_names = {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
            2: "IGMP",
            58: "ICMPv6",
            89: "OSPF",
            132: "SCTP",
            88: "EIGRP"
        }
        return protocol_names.get(protocol, f"Proto {protocol}")

    def _parse_ethernet_layer(self, packet, result):
        """Разбор Ethernet заголовка (L2)"""
        eth_header = packet[:14]
        eth_proto = struct.unpack("!H", eth_header[12:14])[0]

        result['layers']['Ethernet'] = {
            'dst_mac': eth_header[0:6].hex(':'),
            'src_mac': eth_header[6:12].hex(':'),
            'type': self.get_eth_protocol_name(eth_proto),
            'hex': eth_header.hex(':'),
            'fields': [
                {'name': 'Destination MAC', 'value': eth_header[0:6].hex(':'), 'bytes': eth_header[0:6]},
                {'name': 'Source MAC', 'value': eth_header[6:12].hex(':'), 'bytes': eth_header[6:12]},
                {'name': 'EtherType', 'value': f"0x{eth_proto:04x} ({self.get_eth_protocol_name(eth_proto)})",
                 'bytes': eth_header[12:14]}
            ]
        }
        return eth_proto, packet[14:]

    def _parse_ip_layer(self, packet, result):
        """Разбор IP заголовка (L3)"""
        version = packet[0] >> 4

        if version == 4:
            ip_header = packet[:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

            flags = (iph[4] >> 13) & 0x7
            flags_str = [
                f"Reserved: {(flags >> 2) & 0x1}",
                f"Don't Fragment: {(flags >> 1) & 0x1}",
                f"More Fragments: {flags & 0x1}"
            ]

            ip_layer = {
                'version': 4,
                'header_length': (iph[0] & 0xF) * 4,
                'tos': iph[1],
                'total_length': iph[2],
                'id': iph[3],
                'flags': flags_str,
                'fragment_offset': iph[4] & 0x1FFF,
                'ttl': iph[5],
                'protocol': iph[6],
                'protocol_name': self.get_protocol_name(iph[6]),
                'checksum': f"0x{iph[7]:04x}",
                'src_ip': socket.inet_ntoa(iph[8]),
                'dst_ip': socket.inet_ntoa(iph[9]),
                'fields': [
                    {'name': 'Version', 'value': '4 (IPv4)', 'bytes': bytes([iph[0] >> 4])},
                    {'name': 'Header Length', 'value': f"{(iph[0] & 0xF) * 4} bytes", 'bytes': bytes([iph[0] & 0xF])},
                    {'name': 'Type of Service', 'value': iph[1], 'bytes': bytes([iph[1]])},
                    {'name': 'Total Length', 'value': iph[2], 'bytes': iph[2].to_bytes(2, 'big')},
                    {'name': 'Identification', 'value': iph[3], 'bytes': iph[3].to_bytes(2, 'big')},
                    {'name': 'Flags', 'value': '\n'.join(flags_str), 'bytes': bytes([(iph[4] >> 8) & 0xFF])},
                    {'name': 'Fragment Offset', 'value': iph[4] & 0x1FFF, 'bytes': bytes([iph[4] & 0xFF])},
                    {'name': 'Time to Live', 'value': iph[5], 'bytes': bytes([iph[5]])},
                    {'name': 'Protocol', 'value': f"{iph[6]} ({self.get_protocol_name(iph[6])})", 'bytes': bytes([iph[6]])},
                    {'name': 'Header Checksum', 'value': f"0x{iph[7]:04x}", 'bytes': iph[7].to_bytes(2, 'big')},
                    {'name': 'Source Address', 'value': socket.inet_ntoa(iph[8]), 'bytes': iph[8]},
                    {'name': 'Destination Address', 'value': socket.inet_ntoa(iph[9]), 'bytes': iph[9]}
                ]
            }

            result['layers']['IP'] = ip_layer
            return iph[6], socket.inet_ntoa(iph[8]), socket.inet_ntoa(iph[9]), "IPv4", iph[5], packet[20:]

        elif version == 6:
            ip_header = packet[:40]
            iph = struct.unpack('!IHBB16s16s', ip_header)

            ip_layer = {
                'version': 6,
                'traffic_class': (iph[0] >> 20) & 0xFF,
                'flow_label': iph[0] & 0xFFFFF,
                'payload_length': iph[1],
                'next_header': iph[2],
                'hop_limit': iph[3],
                'src_ip': socket.inet_ntop(socket.AF_INET6, iph[4]),
                'dst_ip': socket.inet_ntop(socket.AF_INET6, iph[5]),
                'fields': [
                    {'name': 'Version', 'value': '6 (IPv6)', 'bytes': bytes([6])},
                    {'name': 'Traffic Class', 'value': (iph[0] >> 20) & 0xFF, 'bytes': bytes([(iph[0] >> 20) & 0xFF])},
                    {'name': 'Flow Label', 'value': iph[0] & 0xFFFFF, 'bytes': (iph[0] & 0xFFFFF).to_bytes(3, 'big')},
                    {'name': 'Payload Length', 'value': iph[1], 'bytes': iph[1].to_bytes(2, 'big')},
                    {'name': 'Next Header', 'value': f"{iph[2]} ({self.get_protocol_name(iph[2])})", 'bytes': bytes([iph[2]])},
                    {'name': 'Hop Limit', 'value': iph[3], 'bytes': bytes([iph[3]])},
                    {'name': 'Source Address', 'value': socket.inet_ntop(socket.AF_INET6, iph[4]), 'bytes': iph[4]},
                    {'name': 'Destination Address', 'value': socket.inet_ntop(socket.AF_INET6, iph[5]), 'bytes': iph[5]}
                ]
            }

            result['layers']['IPv6'] = ip_layer
            return iph[2], socket.inet_ntop(socket.AF_INET6, iph[4]), socket.inet_ntop(socket.AF_INET6, iph[5]), "IPv6", iph[3], packet[40:]

    def _parse_transport_layer(self, packet, protocol, ip_version, result):
        """Разбор транспортного уровня (L4)"""
        if protocol == 6:  # TCP
            tcp_header = packet[:20]
            tcph = struct.unpack('!HHLLBBHHH', tcp_header)

            flags = {
                'FIN': (tcph[5] & 0x01) >> 0,
                'SYN': (tcph[5] & 0x02) >> 1,
                'RST': (tcph[5] & 0x04) >> 2,
                'PSH': (tcph[5] & 0x08) >> 3,
                'ACK': (tcph[5] & 0x10) >> 4,
                'URG': (tcph[5] & 0x20) >> 5,
                'ECE': (tcph[5] & 0x40) >> 6,
                'CWR': (tcph[5] & 0x80) >> 7
            }
            flags_str = [f"{k}: {v}" for k, v in flags.items()]

            result['layers']['TCP'] = {
                'src_port': tcph[0],
                'dst_port': tcph[1],
                'seq_num': tcph[2],
                'ack_num': tcph[3],
                'header_length': (tcph[4] >> 4) * 4,
                'flags': flags_str,
                'window_size': tcph[6],
                'checksum': f"0x{tcph[7]:04x}",
                'urgent_ptr': tcph[8],
                'fields': [
                    {'name': 'Source Port', 'value': tcph[0], 'bytes': tcph[0].to_bytes(2, 'big')},
                    {'name': 'Destination Port', 'value': tcph[1], 'bytes': tcph[1].to_bytes(2, 'big')},
                    {'name': 'Sequence Number', 'value': tcph[2], 'bytes': tcph[2].to_bytes(4, 'big')},
                    {'name': 'Acknowledgment Number', 'value': tcph[3], 'bytes': tcph[3].to_bytes(4, 'big')},
                    {'name': 'Header Length', 'value': f"{(tcph[4] >> 4) * 4} bytes", 'bytes': bytes([tcph[4] >> 4])},
                    {'name': 'Flags', 'value': '\n'.join(flags_str), 'bytes': bytes([tcph[5]])},
                    {'name': 'Window Size', 'value': tcph[6], 'bytes': tcph[6].to_bytes(2, 'big')},
                    {'name': 'Checksum', 'value': f"0x{tcph[7]:04x}", 'bytes': tcph[7].to_bytes(2, 'big')},
                    {'name': 'Urgent Pointer', 'value': tcph[8], 'bytes': tcph[8].to_bytes(2, 'big')}
                ]
            }
            return tcph[0], tcph[1], packet[(tcph[4] >> 4) * 4:]

        elif protocol == 17:  # UDP
            udp_header = packet[:8]
            udph = struct.unpack('!HHHH', udp_header)

            result['layers']['UDP'] = {
                'src_port': udph[0],
                'dst_port': udph[1],
                'length': udph[2],
                'checksum': f"0x{udph[3]:04x}",
                'fields': [
                    {'name': 'Source Port', 'value': udph[0], 'bytes': udph[0].to_bytes(2, 'big')},
                    {'name': 'Destination Port', 'value': udph[1], 'bytes': udph[1].to_bytes(2, 'big')},
                    {'name': 'Length', 'value': udph[2], 'bytes': udph[2].to_bytes(2, 'big')},
                    {'name': 'Checksum', 'value': f"0x{udph[3]:04x}", 'bytes': udph[3].to_bytes(2, 'big')}
                ]
            }
            return udph[0], udph[1], packet[8:]

        elif protocol == 1:  # ICMP
            icmp_header = packet[:4]
            icmph = struct.unpack('!BBH', icmp_header)

            result['layers']['ICMP'] = {
                'type': icmph[0],
                'code': icmph[1],
                'checksum': f"0x{icmph[2]:04x}",
                'fields': [
                    {'name': 'Type', 'value': icmph[0], 'bytes': bytes([icmph[0]])},
                    {'name': 'Code', 'value': icmph[1], 'bytes': bytes([icmph[1]])},
                    {'name': 'Checksum', 'value': f"0x{icmph[2]:04x}", 'bytes': icmph[2].to_bytes(2, 'big')}
                ]
            }
            return None, None, packet[4:]

    def _parse_application_layer(self, transport_packet, protocol, src_port, dst_port, result):
        """Разбор прикладного уровня (L7)"""
        if protocol == 6 and (dst_port == 80 or src_port == 80):  # HTTP
            try:
                if b'HTTP' in transport_packet[:20]:  # Response
                    http = dpkt.http.Response(transport_packet)
                    result['layers']['HTTP'] = {
                        'type': 'Response',
                        'status': http.status,
                        'reason': http.reason,
                        'headers': dict(http.headers),
                        'fields': [
                            {'name': 'Status Line', 'value': f"HTTP/{http.version} {http.status} {http.reason}"},
                            *[{'name': k, 'value': v} for k, v in http.headers.items()]
                        ]
                    }
                else:  # Request
                    http = dpkt.http.Request(transport_packet)
                    result['layers']['HTTP'] = {
                        'type': 'Request',
                        'method': http.method,
                        'uri': http.uri,
                        'version': http.version,
                        'headers': dict(http.headers),
                        'fields': [
                            {'name': 'Request Line', 'value': f"{http.method} {http.uri} HTTP/{http.version}"},
                            *[{'name': k, 'value': v} for k, v in http.headers.items()]
                        ]
                    }
            except Exception as e:
                result['layers']['HTTP'] = {
                    'error': f"HTTP parse error: {str(e)}",
                    'hex': transport_packet.hex(':')
                }

        elif protocol == 17 and (dst_port == 53 or src_port == 53):  # DNS
            try:
                dns = dpkt.dns.DNS(transport_packet)
                dns_layer = {
                    'id': dns.id,
                    'qr': 'Response' if dns.qr else 'Query',
                    'opcode': dns.opcode,
                    'aa': dns.aa,
                    'tc': dns.tc,
                    'rd': dns.rd,
                    'ra': dns.ra,
                    'rcode': dns.rcode,
                    'fields': [
                        {'name': 'Transaction ID', 'value': dns.id},
                        {'name': 'Flags', 'value': f"""
                            QR: {dns.qr} ({'Response' if dns.qr else 'Query'})
                            OPCODE: {dns.opcode}
                            AA: {dns.aa}
                            TC: {dns.tc}
                            RD: {dns.rd}
                            RA: {dns.ra}
                            RCODE: {dns.rcode}
                        """},
                        {'name': 'Questions', 'value': len(dns.qd)},
                        {'name': 'Answers', 'value': len(dns.an)},
                        {'name': 'Authority', 'value': len(dns.ns)},
                        {'name': 'Additional', 'value': len(dns.ar)}
                    ]
                }

                if dns.qd:  # Questions
                    dns_layer['questions'] = [{'name': q.name, 'type': q.type} for q in dns.qd]
                    dns_layer['fields'].extend([
                        {'name': 'Question', 'value': f"Name: {q.name}, Type: {q.type}"}
                        for q in dns.qd
                    ])

                if dns.an:  # Answers
                    dns_layer['answers'] = []
                    for answer in dns.an:
                        ans = {'name': answer.name, 'type': answer.type}
                        if answer.type == dpkt.dns.DNS_A:
                            ans['data'] = socket.inet_ntoa(answer.ip)
                        elif answer.type == dpkt.dns.DNS_AAAA:
                            ans['data'] = socket.inet_ntop(socket.AF_INET6, answer.ip6)
                        dns_layer['answers'].append(ans)
                        dns_layer['fields'].append({
                            'name': 'Answer',
                            'value': f"Name: {answer.name}, Type: {answer.type}, Data: {ans.get('data', '')}"
                        })

                result['layers']['DNS'] = dns_layer
            except Exception as e:
                result['layers']['DNS'] = {
                    'error': f"DNS parse error: {str(e)}",
                    'hex': transport_packet.hex(':')
                }

    def process_packet(self, packet):
        """Основной метод для полного разбора пакета через все уровни"""
        try:
            if isinstance(packet, str):
                try:
                    packet = packet.encode('latin-1')
                except:
                    packet = b''

            result = {
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                'length': len(packet),
                'layers': {},
                'raw': packet
            }

            # Для Windows (нет Ethernet заголовка)
            if platform.system() == "Windows":
                # Парсим IP уровень
                protocol, src_ip, dst_ip, ip_version, ttl, ip_remaining = self._parse_ip_layer(packet, result)

                if protocol is None:
                    return None

                # Парсим транспортный уровень
                src_port, dst_port, transport_remaining = self._parse_transport_layer(
                    ip_remaining, protocol, ip_version, result
                )

                # Парсим прикладной уровень (если есть порты)
                if src_port is not None and dst_port is not None:
                    self._parse_application_layer(
                        transport_remaining, protocol, src_port, dst_port, result
                    )

            # Для Linux/Unix (есть Ethernet заголовок)
            else:
                if len(packet) < 14:
                    return None

                # Парсим Ethernet уровень
                eth_proto, eth_remaining = self._parse_ethernet_layer(packet, result)

                # Парсим IP уровень (только для IPv4/IPv6)
                if eth_proto in (0x0800, 0x86DD):
                    protocol, src_ip, dst_ip, ip_version, ttl, ip_remaining = self._parse_ip_layer(
                        eth_remaining, result
                    )

                    # Парсим транспортный уровень
                    src_port, dst_port, transport_remaining = self._parse_transport_layer(
                        ip_remaining, protocol, ip_version, result
                    )

                    # Парсим прикладной уровень (если есть порты)
                    if src_port is not None and dst_port is not None:
                        self._parse_application_layer(
                            transport_remaining, protocol, src_port, dst_port, result
                        )

            # Обновляем статистику
            self._update_stats(result)
            return result

        except Exception as e:
            print(f"Error parsing packet: {e}")
            return None

    def _update_stats(self, result):
        """Обновление статистики на основе разобранного пакета"""
        self.packet_count += 1

        if 'IP' in result['layers']:
            protocol_name = result['layers']['IP'].get('protocol_name', 'Unknown')
            self.protocol_stats[protocol_name] += 1

            if 'TCP' in result['layers']:
                conn_key = (
                    f"{result['layers']['IP']['src_ip']}:{result['layers']['TCP']['src_port']} -> "
                    f"{result['layers']['IP']['dst_ip']}:{result['layers']['TCP']['dst_port']}"
                )
                self.connection_stats[conn_key] += 1
            elif 'UDP' in result['layers']:
                conn_key = (
                    f"{result['layers']['IP']['src_ip']}:{result['layers']['UDP']['src_port']} -> "
                    f"{result['layers']['IP']['dst_ip']}:{result['layers']['UDP']['dst_port']}"
                )
                self.connection_stats[conn_key] += 1