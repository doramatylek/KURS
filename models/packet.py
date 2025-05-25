from dataclasses import dataclass

@dataclass
class Packet:
    number: int
    timestamp: str
    source: str
    destination: str
    protocol: str
    length: int
    info: str
    raw_data: bytes