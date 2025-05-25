"""
Packet Analyzer - сетевой анализатор пакетов с GUI интерфейсом

Основные компоненты:
- core: Бизнес-логика захвата и анализа пакетов
- gui: Графический интерфейс пользователя
- models: Модели данных
"""

__version__ = "1.0.0"
__author__ = "Darya"
__license__ = "MIT"

# Импорты для удобного доступа к основным классам
from .gui.main_window import MainWindow
from .core.capture import PacketCapture
from .models.packet import Packet

__all__ = ['MainWindow', 'PacketCapture', 'Packet']