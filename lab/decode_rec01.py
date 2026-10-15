# -*- coding: utf-8 -*-
from collections import Counter
from pathlib import Path
import sys

# Добавляем корень проекта в пути поиска Python, чтобы работали импорты из lab
root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from lab.capture import read_frames, load_segments

def main():
    # Путь к файлу относительно корня проекта
    pcap_path = root_dir / "data" / "stand" / "rec01.pcapng"
    if not pcap_path.exists():
        print(f"Ошибка: файл {pcap_path} не найден!")
        return

    print(f"Начинаем разбор файла: {pcap_path}")
    
    # Инициализируем диагностический счетчик
    diag = Counter()
    
    # Читаем кадры
    frames = list(read_frames(str(pcap_path), diag))
    print(f"Успешно прочитано кадров: {len(frames)}")
    print(f"Диагностика захвата: {diag}")
    
    # Пытаемся загрузить сегменты
    try:
        segments = list(load_segments(str(pcap_path), diag))
        print(f"Успешно загружено TCP-сегментов: {len(segments)}")
    except Exception as e:
        print(f"Загрузка сегментов через load_segments: {e}")

if __name__ == "__main__":
    main()