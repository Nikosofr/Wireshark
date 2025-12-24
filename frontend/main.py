from customtkinter import *
import tkinter as tk
from tkinter import ttk
from consts import *
import random
import time

# Метод обновления экрана
def auto_update():
    # Здесь добавь логику загрузки данных (Не забудь очистить предыдущие):
    # Пока здесь будет загрузка рандомных данных
    insert_into_table(random.randint(0, 50), time.strftime("%H"), "Me", "Someone else", "ABC", "There's a very important information right there")
    app.after(UPDATE_DELAY, auto_update)

# Метод для добавления данных в таблицу
def insert_into_table(ID, time:str, source:str, destination:str, protocol:str, info:str):
    table.insert("", "end", None, values=(str(ID), time, source, destination, protocol, info))

def main():
    global table, app
    # Создаём общее приложение
    app = CTk()
    app.geometry(f"{WIDTH}x{HEIGHT}")
    app.configure(background=BG_COLOR)

    # Создаём таблицу
    table = ttk.Treeview(app, columns=("Номер", "Время", "Источник", "Цель", "Протокол", "Информация"))
    # Создаём стиль для таблицы
    table_style = ttk.Style()
    # Настраиваем стиль таблицы
    table_style.configure("Treeview", font=("Arial", 11), background=BG_COLOR, foreground=TEXT_COLOR, borderwidth=3)
    table_style.configure("Treeview.Heading", font=("Arial", 13, "bold"))

    # Настраиваем таблицу
    table.column("#0", width=0, stretch=False)
    table.column("Номер", width=int(WIDTH*0.05))
    table.column("Время", width=int(WIDTH*0.14))
    table.column("Источник", width=int(WIDTH*0.17))
    table.column("Цель", width=int(WIDTH*0.17))
    table.column("Протокол", width=int(WIDTH*0.08))
    table.column("Информация", width=int(WIDTH * 0.37))
    table.heading("Номер", text="Номер")
    table.heading("Время", text="Время")
    table.heading("Источник", text="Источник")
    table.heading("Цель", text="Цель")
    table.heading("Протокол", text="Протокол")
    table.heading("Информация", text="Информация")

    # Размещаем таблицу
    table.pack(expand=True, fill="both")

    # Автоматическое обновление
    auto_update()
    # Запускаем основной цикл приложение
    app.mainloop()

# Правильная структура
# Позволяет делать импорт из мейна (Надеюсь нам это не понадобится)
if __name__ == "__main__":
    main()