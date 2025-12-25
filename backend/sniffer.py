"""
Основной модуль сниффера пакетов
"""
import threading
import time
import socket
from collections import deque
from datetime import datetime
from enum import Enum

# Импортируем парсеры протоколов
from backend.protocols.ethernet import parse_ethernet

class Protocol(Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    ARP = "ARP"
    HTTP = "HTTP"
    DNS = "DNS"
    OTHER = "OTHER"

class PacketSniffer:
    def __init__(self, interface=None, max_packets=1000):
        self.interface = interface
        self.max_packets = max_packets
        self.packets = deque(maxlen=max_packets)
        self.sniffing = False
        self.thread = None
        self.callback = None
        self.packet_id = 0
        
    def get_default_interface(self):
        """Получить интерфейс по умолчанию"""
        import netifaces
        for iface in netifaces.interfaces():
            if iface != 'lo' and netifaces.AF_INET in netifaces.ifaddresses(iface):
                return iface
        return 'eth0'
    
    def start_sniffing(self, callback=None):
        """Запустить захват пакетов"""
        if self.sniffing:
            return
            
        self.callback = callback
        self.sniffing = True
        self.interface = self.interface or self.get_default_interface()
        
        # Запускаем сниффер в отдельном потоке
        self.thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.thread.start()
    
    def _sniff_loop(self):
        """Основной цикл захвата пакетов"""
        from scapy.all import sniff, conf
        
        def process_packet(packet):
            """Обработка каждого пакета"""
            try:
                # Получаем сырые данные пакета
                raw_data = bytes(packet)
                
                # Парсим пакет
                parsed = parse_ethernet(raw_data)
                
                # Создаем запись пакета
                packet_record = {
                    'id': self.packet_id,
                    'time': datetime.now().strftime("%H:%M:%S.%f")[:-3],
                    'source': parsed.get('source', 'N/A'),
                    'destination': parsed.get('destination', 'N/A'),
                    'protocol': parsed.get('protocol', Protocol.OTHER.value),
                    'info': parsed.get('info', ''),
                    'length': len(raw_data),
                    'raw': raw_data
                }
                
                self.packet_id += 1
                self.packets.append(packet_record)
                
                # Вызываем callback для обновления GUI
                if self.callback:
                    self.callback(packet_record)
                    
            except Exception as e:
                print(f"Ошибка обработки пакета: {e}")
        
        # Начинаем сниффинг с помощью scapy
        try:
            sniff(iface=self.interface, 
                  prn=process_packet, 
                  store=False,
                  stop_filter=lambda x: not self.sniffing)
        except Exception as e:
            print(f"Ошибка сниффинга: {e}")
            self.sniffing = False
    
    def stop_sniffing(self):
        """Остановить захват пакетов"""
        self.sniffing = False
        if self.thread:
            self.thread.join(timeout=2)
    
    def get_recent_packets(self, count=50):
        """Получить последние пакеты"""
        return list(self.packets)[-count:]
    
    def clear_packets(self):
        """Очистить все пакеты"""
        self.packets.clear()
        self.packet_id = 0
    
    def get_packet_count(self):
        """Получить количество захваченных пакетов"""
        return len(self.packets)