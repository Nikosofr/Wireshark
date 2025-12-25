"""
Основной файл GUI приложения
"""
import customtkinter as ctk
from tkinter import ttk
from datetime import datetime
import threading
import queue

# Импортируем бэкенд
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from backend.sniffer import PacketSniffer
from frontend.consts import *

class PacketSnifferGUI:
    def __init__(self):
        self.app = ctk.CTk()
        self.app.geometry(f"{WIDTH}x{HEIGHT}")
        self.app.title("Simple Packet Sniffer")
        self.app.configure(fg_color=BG_COLOR)
        
        # Очередь для обмена данными между потоками
        self.packet_queue = queue.Queue()
        
        # Создаем сниффер
        self.sniffer = PacketSniffer(max_packets=MAX_PACKETS)
        
        # Создаем GUI элементы
        self.setup_gui()
        
        # Запускаем обновление GUI
        self.auto_update()
        
        # Запускаем захват пакетов автоматически
        self.start_sniffing()
    
    def setup_gui(self):
        """Настройка интерфейса"""
        # Основной фрейм
        main_frame = ctk.CTkFrame(self.app, fg_color=BG_COLOR)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Панель управления
        control_frame = ctk.CTkFrame(main_frame, fg_color=BG_COLOR)
        control_frame.pack(fill="x", pady=(0, 10))
        
        # Кнопки управления
        self.start_btn = ctk.CTkButton(
            control_frame, 
            text="⏻  Start", 
            command=self.start_sniffing,
            fg_color="#36BBCE",
            hover_color="#218838"
        )
        self.start_btn.pack(side="left", padx=5)
        
        self.stop_btn = ctk.CTkButton(
            control_frame, 
            text="🚫 Stop", 
            command=self.stop_sniffing,
            fg_color="#36BBCE",
            hover_color="#c82333"
        )
        self.stop_btn.pack(side="left", padx=5)
        
        self.clear_btn = ctk.CTkButton(
            control_frame, 
            text="🗑️ Clear", 
            command=self.clear_packets
        )
        self.clear_btn.pack(side="left", padx=5)
        
        # Статус
        self.status_label = ctk.CTkLabel(
            control_frame,
            text="Status: Stopped",
            text_color=TEXT_COLOR
        )
        self.status_label.pack(side="right", padx=20)
        
        # Счетчик пакетов
        self.packet_count_label = ctk.CTkLabel(
            control_frame,
            text="Packets: 0",
            text_color=TEXT_COLOR
        )
        self.packet_count_label.pack(side="right", padx=20)
        
        # Создаем таблицу для отображения пакетов
        self.create_packet_table(main_frame)
    
    def create_packet_table(self, parent):
        """Создание таблицы для отображения пакетов"""
        # Создаем фрейм для таблицы
        table_frame = ctk.CTkFrame(parent)
        table_frame.pack(fill="both", expand=True)
        
        # Создаем Treeview (таблицу)
        columns = ("No", "⏱ Time", "📤 Source", "📤 Destination", "🔗 Protocol", "Length", "📌 Info")
        self.table = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            height=25
        )
        
        # Настраиваем стиль
        style = ttk.Style()
        style.configure("Treeview",
                        background="#5F2580",
                        foreground=TEXT_COLOR,
                        fieldbackground="#5F2580",
                        borderwidth=0)
        style.configure("Treeview.Heading",
                        background="#5F2580",
                        foreground=TEXT_COLOR,
                        relief="flat")
        style.map("Treeview.Heading",
                  background=[('active', '#4c4c4c')])
        
        # Настраиваем колонки
        col_widths = {
            "No": 50,
            "Time": 100,
            "Source": 180,
            "Destination": 180,
            "Protocol": 80,
            "Length": 70,
            "Info": 400
        }
        
        for col in columns:
            self.table.heading(col, text=col)
            self.table.column(col, width=col_widths.get(col, 100))
        
        # Добавляем скроллбар
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=scrollbar.set)
        
        # Размещаем элементы
        self.table.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
    
    def packet_callback(self, packet):
        """Callback для приема пакетов из сниффера"""
        # Добавляем пакет в очередь для обработки в основном потоке
        self.packet_queue.put(packet)
    
    def process_queued_packets(self):
        """Обработка пакетов из очереди"""
        try:
            while True:
                packet = self.packet_queue.get_nowait()
                self.insert_packet_into_table(packet)
        except queue.Empty:
            pass
    
    def insert_packet_into_table(self, packet):
        """Вставка пакета в таблицу"""
        # Форматируем данные для таблицы
        values = (
            str(packet['id']),
            packet['time'],
            packet['source'],
            packet['destination'],
            packet['protocol'],
            str(packet['length']),
            packet['info']
        )
        
        # Вставляем в начало таблицы (новые пакеты сверху)
        self.table.insert("", 0, values=values)
        
        # Ограничиваем количество строк
        if len(self.table.get_children()) > MAX_PACKETS:
            self.table.delete(self.table.get_children()[-1])
        
        # Обновляем счетчик
        self.packet_count_label.configure(text=f"Packets: {self.sniffer.get_packet_count()}")
    
    def start_sniffing(self):
        """Запуск захвата пакетов"""
        if not self.sniffer.sniffing:
            self.sniffer.start_sniffing(self.packet_callback)
            self.status_label.configure(text="Status: Sniffing...", text_color="#28a745")
            self.start_btn.configure(state="disabled")
            self.stop_btn.configure(state="normal")
    
    def stop_sniffing(self):
        """Остановка захвата пакетов"""
        if self.sniffer.sniffing:
            self.sniffer.stop_sniffing()
            self.status_label.configure(text="Status: Stopped", text_color="#dc3545")
            self.start_btn.configure(state="normal")
            self.stop_btn.configure(state="disabled")
    
    def clear_packets(self):
        """Очистка всех пакетов"""
        self.sniffer.clear_packets()
        for item in self.table.get_children():
            self.table.delete(item)
        self.packet_count_label.configure(text="Packets: 0")
    
    def auto_update(self):
        """Автоматическое обновление GUI"""
        # Обрабатываем пакеты из очереди
        self.process_queued_packets()
        
        # Планируем следующее обновление
        self.app.after(UPDATE_DELAY, self.auto_update)
    
    def run(self):
        """Запуск приложения"""
        self.app.mainloop()

def main():
    """Основная функция"""
    # Настройка темы
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    
    # Создание и запуск GUI
    gui = PacketSnifferGUI()
    gui.run()

if __name__ == "__main__":
    main()