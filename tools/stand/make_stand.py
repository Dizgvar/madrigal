"""Стенд: придуманное «устройство» и клиент. Строит НАСТОЯЩИЕ байты Ethernet/IPv4/TCP,
пишет pcap/pcapng и журнал действий. Умеет портить запись (перестановка, повтор, потеря...).
ПРАВИЛО: кто пишет стенд, НЕ участвует в исследовании этого протокола и никому его не рассказывает."""
import csv
import random
import struct
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

CLIENT, SERVER = ("10.0.0.5", 51000), ("10.0.0.9", 5020)
MSS, SYN, FIN, RST, ACK = 1460, 2, 1, 4, 0x10
T0 = 1_760_000_000_000_000          # микросекунды от 1970


# ---------- «секретный» протокол устройства ----------
def xor8(b):
    x = 0
    for c in b:
        x ^= c
    return x


def msg(cmd, req_id, payload):
    body = b"\xD1\x7E" + len(payload).to_bytes(2, "big") + bytes([cmd, req_id]) + payload
    return body + bytes([xor8(body)])


def enc(pid, v):                    # параметр 2 - 32 бита, остальные - 16
    return v.to_bytes(4 if pid == 2 else 2, "big", signed=True)


def do_action(params, rnd, req_id, kind, args):
    if kind == "read":
        pid = args[0]
        return (msg(1, req_id, bytes([pid])), msg(0x81, req_id, bytes([pid]) + enc(pid, params[pid])),
                str(params[pid]))
    if kind == "write":
        pid, v = args
        params[pid] = v
        return msg(2, req_id, bytes([pid]) + enc(pid, v)), msg(0x82, req_id, bytes([pid, 0])), "ok"
    n = args[0]                      # measure
    s = [params[1] * 10 + rnd.randint(-8, 8) for _ in range(n)]
    resp = n.to_bytes(2, "big") + b"".join(x.to_bytes(2, "big", signed=True) for x in s)
    return msg(3, req_id, n.to_bytes(2, "big")), msg(0x83, req_id, resp), "n=%d avg=%.1f" % (n, sum(s) / n / 10)


# ---------- сборка пакетов ----------
def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def mac(ip):
    return bytes([2, 0, 0, 0, 0, int(ip.split(".")[-1])])


def build_frame(src, dst, seq, ack, flags, payload=b"", ip_id=1):
    tcp = struct.pack("!HHIIBBHHH", src[1], dst[1], seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 5 << 4, flags, 65535, 0, 0) + payload
    s_ip, d_ip = bytes(map(int, src[0].split("."))), bytes(map(int, dst[0].split(".")))
    tcp = tcp[:16] + struct.pack("!H", csum(s_ip + d_ip + b"\0\x06" + struct.pack("!H", len(tcp)) + tcp)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), ip_id, 0x4000, 64, 6, 0, s_ip, d_ip)
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    return mac(dst[0]) + mac(src[0]) + b"\x08\x00" + ip + tcp


@dataclass
class Pkt:
    ts_us: int
    meta: tuple = None        # (src, dst, seq, ack, flags, payload)
    raw: bytes = None         # готовый кадр (например ARP)
    cut: int = None           # сколько байт кадра сохранить в файле (имитация snaplen)
    break_csum: bool = False
    zero_csum: bool = False   # имитация checksum offloading

    def frame(self):
        fr = self.raw if self.raw is not None else build_frame(*self.meta)
        if self.break_csum:
            fr = fr[:50] + bytes([fr[50] ^ 0xFF]) + fr[51:]
        if self.zero_csum:
            fr = fr[:50] + b"\0\0" + fr[52:]
        return fr


def session(actions, seed, cport=51000, t0=T0, clock_offset_s=0.3):
    """-> (пакеты, строки журнала действий, ожидаемые потоки (только для тестов стенда))."""
    rnd, pk, rows = random.Random(seed), [], []
    cli, srv = (CLIENT[0], cport), SERVER
    c_seq, s_seq = rnd.randrange(1 << 32), rnd.randrange(1 << 32)
    params, t = {1: 20, 2: 100, 3: 5}, t0
    exp = {"c2s": b"", "s2c": b""}
    pk.append(Pkt(t, (cli, srv, c_seq, 0, SYN)));            c_seq += 1
    pk.append(Pkt(t + 300, (srv, cli, s_seq, c_seq, SYN | ACK)));  s_seq += 1
    pk.append(Pkt(t + 600, (cli, srv, c_seq, s_seq, ACK)))
    for i, (dt, kind, *args) in enumerate(actions):
        t = t0 + int(dt * 1_000_000)
        req, resp, result = do_action(params, rnd, (i + 1) % 256, kind, args)
        exp["c2s"] += req
        exp["s2c"] += resp
        for k in range(0, len(req), MSS):
            ch = req[k:k + MSS]
            pk.append(Pkt(t + k // MSS * 100, (cli, srv, c_seq, s_seq, ACK, ch)))
            c_seq += len(ch)
        pk.append(Pkt(t + 1000, (srv, cli, s_seq, c_seq, ACK)))
        for k in range(0, len(resp), MSS):
            ch = resp[k:k + MSS]
            pk.append(Pkt(t + 2000 + k // MSS * 100, (srv, cli, s_seq, c_seq, ACK, ch)))
            s_seq += len(ch)
        pk.append(Pkt(t + 2000 + (len(resp) // MSS + 1) * 100 + 50, (cli, srv, c_seq, s_seq, ACK)))
        shown = datetime.fromtimestamp(t / 1e6 + clock_offset_s, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        rows.append([shown, kind, args[0] if args else "", args[1] if len(args) > 1 else "", result])
    t += 5_000_000
    pk.append(Pkt(t, (cli, srv, c_seq, s_seq, FIN | ACK)))
    pk.append(Pkt(t + 300, (srv, cli, s_seq, c_seq + 1, ACK)))
    pk.append(Pkt(t + 600, (srv, cli, s_seq, c_seq + 1, FIN | ACK)))
    pk.append(Pkt(t + 900, (cli, srv, c_seq + 1, s_seq + 1, ACK)))
    return pk, rows, exp


def noise(t0, seed):
    """Фоновое соединение + ARP-кадр: приложение должно их пережить и не смешать с целевым обменом."""
    rnd = random.Random(seed)
    a, b, s1, s2 = ("10.0.0.6", 40000), ("10.0.0.7", 80), 1000, 5000
    out, nxt = [Pkt(t0 + 1500, (a, b, s1, 0, SYN))], s1 + 1
    for k in range(5):
        body = bytes(rnd.randrange(256) for _ in range(rnd.randrange(20, 300)))
        out.append(Pkt(t0 + 3_000_000 * (k + 1), (a, b, nxt, s2, ACK, body)))
        nxt += len(body)
    arp = b"\xff" * 6 + mac("10.0.0.5") + b"\x08\x06" + bytes(28)
    return out + [Pkt(t0 + 2_500_000, raw=arp)]


# ---------- порча записи (каждая функция меняет список на месте) ----------
def swap(pk, i, j):
    pk[i], pk[j] = pk[j], pk[i]
    pk[i].ts_us, pk[j].ts_us = pk[j].ts_us, pk[i].ts_us      # время принадлежит месту в записи

def duplicate(pk, i):
    pk.insert(i + 1, Pkt(pk[i].ts_us + 10, pk[i].meta, pk[i].raw))

def drop(pk, i):
    del pk[i]

def truncate(pk, i, keep):
    pk[i].cut = keep

def conflict(pk, i):
    m = list(pk[i].meta)
    m[5] = bytes([m[5][0] ^ 0xFF]) + m[5][1:]                 # другой байт, КОНТРОЛЬНАЯ СУММА ВЕРНА
    pk.insert(i + 1, Pkt(pk[i].ts_us + 10, tuple(m)))

def break_checksum(pk, i):
    pk[i].break_csum = True

def drop_handshake(pk):
    del pk[:3]

def offload(pk, src_ip="10.0.0.5"):
    for p in pk:
        if p.meta and p.meta[0][0] == src_ip:
            p.zero_csum = True

def data_idx(pk, direction="c2s", n=0):
    """Индекс n-го пакета с данными в направлении (для выбора жертвы порчи)."""
    who = CLIENT[0] if direction == "c2s" else SERVER[0]
    return [i for i, p in enumerate(pk) if p.meta and len(p.meta) > 5 and p.meta[0][0] == who and p.meta[5]][n]


# ---------- запись файлов ----------
def write_pcap(path, pkts, snaplen=65535):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, 1))
        for p in pkts:
            fr = p.frame()
            data = fr[:p.cut] if p.cut is not None else fr
            f.write(struct.pack("<IIII", p.ts_us // 1_000_000, p.ts_us % 1_000_000, len(data), len(fr)) + data)


def _blk(btype, body):
    pad = (-len(body)) % 4
    total = 12 + len(body) + pad
    return struct.pack("<II", btype, total) + body + b"\0" * pad + struct.pack("<I", total)


def write_pcapng(path, pkts, nano=False):
    idb = struct.pack("<HHI", 1, 0, 65535)
    if nano:                                                   # опция if_tsresol = 9 (наносекунды)
        idb += struct.pack("<HH", 9, 1) + b"\x09\0\0\0" + struct.pack("<HH", 0, 0)
    out = [_blk(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)), _blk(1, idb)]
    for p in pkts:
        fr = p.frame()
        data = fr[:p.cut] if p.cut is not None else fr
        ts = p.ts_us * (1000 if nano else 1)
        out.append(_blk(6, struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(data), len(fr)) + data))
    Path(path).write_bytes(b"".join(out))


def write_log(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["time_utc", "action", "param", "value", "result"])
        w.writerows(rows)


ACTIONS_1 = [(1.0, "read", 1), (2.0, "write", 1, 21), (3.0, "read", 1), (4.0, "measure", 10),
             (5.0, "write", 1, 30), (6.0, "measure", 10), (7.0, "read", 3), (8.0, "measure", 600),
             (9.5, "write", 3, 2), (10.5, "measure", 20000)]
ACTIONS_2 = [(0.5, "read", 2), (1.5, "write", 2, 100000), (2.5, "read", 2), (3.5, "write", 1, 25),
             (4.5, "measure", 50), (5.5, "read", 1), (6.5, "measure", 3000)]


def main(out_dir):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    def make(actions, seed, **kw):
        pk, rows, exp = session(actions, seed, **kw)
        return sorted(pk + noise(T0, seed), key=lambda p: p.ts_us), rows

    pk, rows = make(ACTIONS_1, 1)
    write_pcapng(out / "rec01.pcapng", pk);  write_log(out / "rec01_actions.csv", rows)
    pk, rows = make(ACTIONS_2, 2, cport=51001)
    write_pcap(out / "rec02.pcap", pk);      write_log(out / "rec02_actions.csv", rows)
    # дефекты строим из чистой записи; имена файлов приложение использовать НЕ вправе
    def defect(name, fn):
        pk, _ = make(ACTIONS_1, 1)
        fn(pk)
        (write_pcapng if name.endswith("ng") else write_pcap)(out / ("def_" + name), pk)
    big = lambda pk: data_idx(pk, "s2c", 9)       # один из пакетов длинного ответа
    defect("reorder.pcap", lambda pk: swap(pk, big(pk), data_idx(pk, "s2c", 10)))
    defect("dup.pcap", lambda pk: duplicate(pk, big(pk)))
    defect("loss.pcap", lambda pk: drop(pk, big(pk)))
    defect("snaplen.pcap", lambda pk: truncate(pk, big(pk), 200))
    defect("conflict.pcap", lambda pk: conflict(pk, big(pk)))
    defect("nostart.pcap", drop_handshake)
    defect("badcsum.pcap", lambda pk: break_checksum(pk, big(pk)))
    defect("offload.pcap", offload)
    print("готово:", sorted(p.name for p in out.iterdir()))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "data/stand")
