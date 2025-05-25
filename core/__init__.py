"""
Модуль core содержит основную логику работы анализатора пакетов

Доступные классы:
- PacketCapture: Захват сетевых пакетов
- PacketAnalyzer: Анализ и обработка пакетов
- ProtocolParser: Разбор протоколов разных уровней
"""

from .capture import PacketCapture
from .analyzer import PacketAnalyzer
from .protocols import ProtocolParser
from .utils import get_interfaces, validate_packet

__all__ = ['PacketCapture', 'PacketAnalyzer', 'ProtocolParser', 'get_interfaces', 'validate_packet']