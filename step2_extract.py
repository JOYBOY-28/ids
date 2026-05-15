import time
import threading
from scapy.layers.inet import IP, TCP, UDP, ICMP

from step1_capture import packet_buffer

feature_list = []
_last_pkt_time = None
_lock = threading.Lock()

EXTRACT_INTERVAL = 5  # seconds


def _proto_encode(pkt):
    if pkt.haslayer(TCP):
        return 0
    if pkt.haslayer(UDP):
        return 1
    if pkt.haslayer(ICMP):
        return 2
    return 3


def _tcp_flags(pkt):
    defaults = {"flag_syn": 0, "flag_ack": 0, "flag_fin": 0, "flag_rst": 0, "flag_psh": 0}
    if not pkt.haslayer(TCP):
        return defaults
    flags = pkt[TCP].flags
    return {
        "flag_syn": int(bool(flags & 0x02)),
        "flag_ack": int(bool(flags & 0x10)),
        "flag_fin": int(bool(flags & 0x01)),
        "flag_rst": int(bool(flags & 0x04)),
        "flag_psh": int(bool(flags & 0x08)),
    }


def _extract_features(pkt):
    global _last_pkt_time

    if not pkt.haslayer(IP):
        return None

    ip = pkt[IP]

    # Base network
    src_ip = ip.src
    dst_ip = ip.dst
    src_port = 0
    dst_port = 0
    if pkt.haslayer(TCP):
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport

    # IP data
    ip_ttl = ip.ttl
    raw_flags = int(ip.flags)
    ip_flag_df = int(bool(raw_flags & 0x2))
    ip_flag_mf = int(bool(raw_flags & 0x1))
    payload_len = len(ip.payload)

    # Delta time
    current_time = float(pkt.time)
    delta_t = 0.0 if _last_pkt_time is None else current_time - _last_pkt_time
    _last_pkt_time = current_time

    feature = {
        "src_ip":      src_ip,
        "dst_ip":      dst_ip,
        "src_port":    src_port,
        "dst_port":    dst_port,
        "ip_ttl":      ip_ttl,
        "ip_flag_df":  ip_flag_df,
        "ip_flag_mf":  ip_flag_mf,
        "payload_len": payload_len,
        "delta_t":     delta_t,
        "proto":       _proto_encode(pkt),
    }
    feature.update(_tcp_flags(pkt))
    return feature


def _extraction_loop():
    while True:
        time.sleep(EXTRACT_INTERVAL)
        packets = packet_buffer.drain()
        if not packets:
            continue
        with _lock:
            for pkt in packets:
                feat = _extract_features(pkt)
                if feat is not None:
                    feature_list.append(feat)


def start_extraction():
    t = threading.Thread(target=_extraction_loop, daemon=True)
    t.start()
    return t


if __name__ == "__main__":
    worker = start_extraction()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
