"""
Модуль gui содержит графический интерфейс пользователя

Компоненты:
- MainWindow: Главное окно приложения
- PacketTree: Виджет для отображения пакетов
- DetailsText: Виджет для отображения деталей
- ViewerWindow: Окно просмотра сохраненных сессий
"""

from .main_window import MainWindow
from .widgets import PacketTree, DetailsText
from .viewer_window import ViewerWindow

__all__ = ['MainWindow', 'PacketTree', 'DetailsText', 'ViewerWindow']