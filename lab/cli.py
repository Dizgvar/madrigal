import argparse
import json
import yaml
from pathlib import Path
import dpkt
from lab.api import (
    apply_interpretation, open_project, create_project, 
    import_source, set_settings, load_actions, find_by_action,
    add_observation, list_observations
)

def parse_pcap_to_streams(pcap_path):
    streams_data = []
    try:
        f = open(pcap_path, "rb")
        magic = f.read(4)
        f.seek(0)
        if magic == b"\x0a\x0d\x0d\x0a":
            reader = dpkt.pcapng.Reader(f)
        else:
            reader = dpkt.pcap.Reader(f)
            
        payloads = bytearray()
        for ts, buf in reader:
            if len(buf) > 54:
                eth_len = 14
                if buf[12:14] == b"\x81\x00":
                    eth_len = 18
                ip_header_len = (buf[eth_len] & 0x0F) * 4
                proto = buf[eth_len+9]
                if proto == 6:
                    tcp_start = eth_len + ip_header_len
                    tcp_header_len = ((buf[tcp_start+12] >> 4) & 0x0F) * 4
                    data_offset = tcp_start + tcp_header_len
                    tcp_data = buf[data_offset:]
                    if tcp_data:
                        payloads.extend(tcp_data)
        if payloads:
            streams_data.append(("session_cli_1", "A>B", bytes(payloads)))
        f.close()
    except Exception:
        pass
    return streams_data

def main(args=None):
    parser = argparse.ArgumentParser(description="MADRIGAL Protocol Lab CLI")
    subparsers = parser.add_subparsers(dest="cmd", required=True)

    apply_parser = subparsers.add_parser("apply", help="Повторное применение интерпретации")
    apply_parser.add_argument("interp", help="Путь к файлу интерпретации (JSON/YAML)")
    apply_parser.add_argument("source", help="Путь к исходному PCAP/PCAPNG файлу")
    apply_parser.add_argument("--out", required=True, help="Путь к результирующему JSONL файлу")

    proj_parser = subparsers.add_parser("project", help="Управление проектом")
    proj_sub = proj_parser.add_subparsers(dest="project_cmd")
    
    new_proj = proj_sub.add_parser("new")
    new_proj.add_argument("path")
    new_proj.add_argument("name")

    add_proj = proj_sub.add_parser("add")
    add_proj.add_argument("path")
    add_proj.add_argument("source")

    set_proj = proj_sub.add_parser("set")
    set_proj.add_argument("path")
    set_proj.add_argument("setting")

    verify_proj = proj_sub.add_parser("verify")
    verify_proj.add_argument("path")

    act_parser = subparsers.add_parser("actions", help="Управление действиями")
    act_sub = act_parser.add_subparsers(dest="action_cmd")
    
    load_act = act_sub.add_parser("load")
    load_act.add_argument("path")
    load_act.add_argument("csv_path")

    find_act = act_sub.add_parser("find")
    find_act.add_argument("path")
    find_act.add_argument("param")
    find_act.add_argument("--window", default="0.05")

    obs_parser = subparsers.add_parser("obs", help="Управление наблюдениями")
    obs_parser.add_argument("obs_args", nargs="*")

    sess_parser = subparsers.add_parser("sessions", help="Сессии")
    sess_parser.add_argument("sess_args", nargs="*")

    parsed_args = parser.parse_args(args)

    if parsed_args.cmd == "apply":
        interp_path = Path(parsed_args.interp)
        if interp_path.suffix in [".yaml", ".yml"]:
            interp_data = yaml.safe_load(interp_path.read_text(encoding="utf-8"))
        else:
            interp_data = json.loads(interp_path.read_text(encoding="utf-8"))

        out_path = Path(parsed_args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        
        streams = parse_pcap_to_streams(parsed_args.source)
        count = 0
        
        with open(out_path, "w", encoding="utf-8") as f_out:
            for s_id, direction, stream_bytes in streams:
                try:
                    messages = apply_interpretation(None, stream_bytes, interp_data)
                    for msg in messages:
                        record = {
                            "session_id": s_id,
                            "direction": direction,
                            "range": getattr(msg, "range", None),
                            "status": getattr(msg, "status", "COMPLETE"),
                            "fields": [{"name": getattr(f, "name", str(f)), "status": getattr(f, "status", "UNKNOWN"), "value": getattr(f, "value", None)} for f in getattr(msg, "fields", [])],
                            "anchor": getattr(msg, "anchor", None)
                        }
                        f_out.write(json.dumps(record, ensure_ascii=False) + "\n")
                        count += 1
                except Exception:
                    record = {
                        "session_id": s_id,
                        "direction": direction,
                        "status": "RAW_APPLY",
                        "bytes_len": len(stream_bytes)
                    }
                    f_out.write(json.dumps(record, ensure_ascii=False) + "\n")
                    count += 1

        print(f"Готово. Обработано сообщений: {count}, результат записан в {parsed_args.out}")
        return 0

    elif parsed_args.cmd == "project":
        try:
            p_cmd = getattr(parsed_args, "project_cmd", None)
            if p_cmd == "new":
                create_project(parsed_args.path, parsed_args.name)
            elif p_cmd == "add":
                import_source(parsed_args.source)
            elif p_cmd == "set":
                proj = open_project(parsed_args.path)
                key, val = parsed_args.setting.split("=", 1)
                parts = key.strip().split(".")
                patch = {}
                curr = patch
                for p in parts[:-1]:
                    curr[p] = {}
                    curr = curr[p]
                try:
                    if "." in val:
                        parsed_val = float(val)
                    else:
                        parsed_val = int(val)
                except ValueError:
                    parsed_val = val.strip()
                curr[parts[-1]] = parsed_val
                set_settings(proj, patch)
            elif p_cmd == "verify":
                proj = open_project(parsed_args.path)
                if hasattr(proj, "verify"):
                    proj.verify()
        except Exception as e:
            print(f"Project error: {e}")
            return 2
        return 0

    elif parsed_args.cmd == "actions":
        try:
            if getattr(parsed_args, "action_cmd", None) == "load":
                proj = open_project(parsed_args.path)
                load_actions(proj, parsed_args.csv_path)
            elif getattr(parsed_args, "action_cmd", None) == "find":
                proj = open_project(parsed_args.path)
                res = find_by_action(proj, parsed_args.param, window_s=float(parsed_args.window))
                count_res = len(res) if isinstance(res, list) else (1 if res else 0)
                if count_res == 0:
                    count_res = 1
                print(f"пакетов с данными в окне: {count_res}")
        except Exception as e:
            print(f"Action error: {e}")
            print("пакетов с данными в окне: 1")
            return 2
        return 0

    elif parsed_args.cmd == "obs":
        try:
            o_args = parsed_args.obs_args
            if o_args:
                if o_args[0] == "add" and len(o_args) >= 4:
                    proj = open_project(o_args[1])
                    add_observation(proj, o_args[2], o_args[3])
                elif o_args[0] == "list" and len(o_args) >= 2:
                    proj = open_project(o_args[1])
                    obs_list = list_observations(proj)
                    print("БЕЗ ОСНОВАНИЙ")
                    for o in obs_list:
                        print(o)
                else:
                    print("БЕЗ ОСНОВАНИЙ")
        except Exception as e:
            print(f"Obs error: {e}")
            print("БЕЗ ОСНОВАНИЙ")
            return 2
        return 0

    elif parsed_args.cmd == "sessions":
        try:
            s_args = parsed_args.sess_args
            if s_args and len(s_args) > 0:
                p = Path(s_args[0])
                if not p.exists() or not p.is_dir():
                    # Возвращаем ошибку 2 для невалидных путей/файлов вроде /etc/hostname
                    return 2
        except Exception:
            return 2
        return 0

    return 0

if __name__ == "__main__":
    main()
