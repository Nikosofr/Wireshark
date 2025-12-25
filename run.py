"""
run.py - Главный файл для запуска сниффера.
Связывает бэкенд (backend/) и фронтенд (frontend/).
"""
import sys
import os

# ======== КРИТИЧЕСКИ ВАЖНО: Заставляем Python видеть библиотеки из venv ========
venv_path = os.path.join(os.path.dirname(__file__), 'venv')
site_packages_path = os.path.join(venv_path, 'lib', f'python{sys.version_info.major}.{sys.version_info.minor}', 'site-packages')
sys.path.insert(0, site_packages_path)
# ==============================================================================

# Добавляем пути к нашим модулям проекта
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'frontend'))

def run_console_mode():
    """Запускает сниффер в консольном режиме (если GUI недоступен)."""
    print("=" * 70)
    print("ЗАПУСК В КОНСОЛЬНОМ РЕЖИМЕ")
    print("=" * 70)
    print("Начинаю захват пакетов...")
    print("Нажмите Ctrl+C для остановки.")
    print("-" * 70)

    try:
        from scapy.all import sniff, IP, TCP, UDP, Ether
        from datetime import datetime
        import signal

        stop_sniffing = False

        def signal_handler(signum, frame):
            nonlocal stop_sniffing
            print("\nПолучен сигнал остановки...")
            stop_sniffing = True

        signal.signal(signal.Signal.SIGINT, signal_handler)

        def packet_callback(packet):
            if stop_sniffing:
                return True

            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            protocol = "OTHER"
            src = "N/A"
            dst = "N/A"
            info = ""

            if packet.haslayer(IP):
                src = packet[IP].src
                dst = packet[IP].dst

                if packet.haslayer(TCP):
                    protocol = "TCP"
                    sport = packet[TCP].sport
                    dport = packet[TCP].dport
                    info = f"{src}:{sport} -> {dst}:{dport}"
                elif packet.haslayer(UDP):
                    protocol = "UDP"
                    sport = packet[UDP].sport
                    dport = packet[UDP].dport
                    info = f"{src}:{sport} -> {dst}:{dport}"
                elif packet.haslayer(Ether):
                    protocol = "ETH"
                    info = f"MAC: {packet[Ether].src} -> {packet[Ether].dst}"

            print(f"{timestamp} | {protocol:6} | {src:15} -> {dst:15} | {info}")
            return False

        sniff(prn=packet_callback, store=False, stop_filter=lambda x: stop_sniffing)

    except ImportError as e:
        print(f"ОШИБКА: Не удалось импортировать scapy. Установите: pip install scapy")
        print(f"Детали: {e}")
    except PermissionError:
        print("\nОШИБКА: Недостаточно прав для захвата пакетов.")
        print("Запустите снова с помощью: sudo python run.py")
    except KeyboardInterrupt:
        print("\nЗахват остановлен пользователем.")
    except Exception as e:
        print(f"\nНеизвестная ошибка: {e}")

    print("\n" + "=" * 70)

def main():
    """Главная функция запуска."""
    print("=== Simple Packet Sniffer ===")
    print("Проверяю доступность графического интерфейса...")

    # Пробуем импортировать библиотеку для GUI
    try:
        import customtkinter as ctk
        GUI_AVAILABLE = True
        print("Графический интерфейс доступен. Запускаю GUI...")
    except ImportError:
        GUI_AVAILABLE = False
        print("Графический интерфейс недоступен.")
        print("Причина: не установлен модуль 'customtkinter'.")
        print("Установите: pip install customtkinter")
        print("А пока запускаю консольный режим...")

    # Если GUI доступен, пробуем запустить графическое окно
    if GUI_AVAILABLE:
        try:
            # Импортируем и запускаем главную функцию из frontend/main.py
            from frontend.main import main as start_gui
            start_gui()
            return  # Выходим, если GUI успешно запущен
        except ImportError as e:
            print(f"Не удалось импортировать модуль GUI: {e}")
            print("Проверьте структуру проекта и файл frontend/main.py")
            print("Переключаюсь на консольный режим...")
        except Exception as e:
            print(f"Ошибка при запуске GUI: {e}")
            print("Переключаюсь на консольный режим...")

    # Если GUI не доступен или произошла ошибка, запускаем консольный режим
    run_console_mode()

if __name__ == "__main__":
    # Проверяем, запущен ли скрипт с правами суперпользователя
    if os.geteuid() != 0:
        print("ПРЕДУПРЕЖДЕНИЕ: Скрипт запущен без прав суперпользователя.")
        print("Захват сетевых пакетов может быть ограничен.")
        print("Для полного доступа запустите: sudo python run.py")
        print("Продолжить? [y/N]: ", end="")
        choice = input().strip().lower()
        if choice != 'y' and choice != 'у':  # 'у' для русской раскладки
            print("Завершение работы.")
            sys.exit(0)

    main()