# -*- coding: utf-8 -*-
from collections import Counter
from pathlib import Path
import sys
import json

root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from lab.capture import file_sha256, load_segments
from lab.streams import split_sessions, build_all
from lab.views import stream_to_dict, session_to_dict

def main():
    pcap_path = root_dir / "data" / "stand" / "rec01.pcapng"
    if not pcap_path.exists():
        print(f"Ошибка: файл {pcap_path} не найден!")
        return

    print(f"Финальная сборка потоков для: {pcap_path}")
    
    diag = Counter()
    source_id = file_sha256(str(pcap_path))
    
    segments = list(load_segments(str(pcap_path), diag))
    sessions = split_sessions(segments, source_id)
    streams = build_all(sessions)
    
    # Ищем нужный поток с большим объемом данных (Сессия 1, направление B>A)
    target_stream_key = None
    for key, stream in streams.items():
        if stream.known_bytes > 40000:  # Тот самый большой поток на 41333 байта
            target_stream_key = key
            break
            
    if target_stream_key:
        stream = streams[target_stream_key]
        print(f"Найден целевой поток: {target_stream_key[0]} | Направление: {target_stream_key[1]}")
        print(f"Объем собранных данных: {stream.known_bytes} байт")
        
        # Получаем полные данные через spans
        spans = stream.spans()
        full_data = bytearray()
        for span in spans:
            if span.kind == "known" and span.data:
                full_data.extend(span.data)
            elif span.kind == "gap":
                # Если в потоке есть дыры, заполняем их нулями или байтами-заглушками по протоколу
                full_data.extend(b'\x00' * (span.end - span.start))
                
        # Сохраняем извлеченные данные в бинарный файл
        output_file = root_dir / "extracted_payload.bin"
        with open(output_file, "wb") as f:
            f.write(full_data)
            
        print(f"Успешно! Полезная нагрузка сохранена в файл: {output_file}")
        print(f"Итоговый размер файла: {len(full_data)} байт")
    else:
        print("Не удалось найти целевой поток с большим объемом данных.")

if __name__ == "__main__":
    main()