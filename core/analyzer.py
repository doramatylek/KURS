from datetime import datetime
from models.packet import Packet

class PacketAnalyzer:
    def __init__(self, protocol_parser):
        self.protocol_parser = protocol_parser

    def process_packet(self, raw_packet, packet_num):
        try:
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            protocol_info = self.protocol_parser.parse(raw_packet)

            if not protocol_info:
                return None

            return Packet(
                number=packet_num,
                timestamp=timestamp,
                source=protocol_info['source'],
                destination=protocol_info['destination'],
                protocol=protocol_info['protocol'],
                length=len(raw_packet),
                info=protocol_info['info'],
                raw_data=raw_packet
            )
        except Exception as e:
            print(f"Packet processing error: {e}")
            return None