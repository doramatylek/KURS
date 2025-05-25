class PacketAnalyzer:
    def __init__(self, protocol_parser):
        self.protocol_parser = protocol_parser
    
    def process_packet(self, packet):
        return self.protocol_parser.parse(packet)