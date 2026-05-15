"""
Stage 1: Live Packet Capture
IDS Project

Deliverable:
- packet_buffer
- start_capture()

Stage 2 can import:
from step1_capture import packet_buffer, start_capture
"""

from collections import deque
from threading import Lock
from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list


# -----------------------------
# Key Variables
# -----------------------------
INTERFACE = "wlo1"      # Change to "Ethernet" if Wi-Fi does not work
MAX_PACKETS = 1000
BPF_FILTER = "ip"


# -----------------------------
# Thread-safe rolling buffer
# -----------------------------
class PacketBuffer:
    def __init__(self, maxlen=MAX_PACKETS):
        self.buffer = deque(maxlen=maxlen)
        self.lock = Lock()

    def add(self, packet):
        with self.lock:
            self.buffer.append(packet)

    def drain(self):
        with self.lock:
            packets = list(self.buffer)
            self.buffer.clear()
            return packets

    def peek(self):
        with self.lock:
            return list(self.buffer)


# Singleton buffer for Stage 2
packet_buffer = PacketBuffer(MAX_PACKETS)


# -----------------------------
# Get protocol and port details
# -----------------------------
def get_packet_details(packet):
    proto = "OTHER"
    src_port = "-"
    dst_port = "-"

    if packet.haslayer(TCP):
        proto = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    elif packet.haslayer(UDP):
        proto = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    elif packet.haslayer(ICMP):
        proto = "ICMP"

    return proto, src_port, dst_port


# -----------------------------
# Packet callback
# -----------------------------
def _packet_callback(packet, verbose=True):
    if packet.haslayer(IP):
        packet_buffer.add(packet)

        if verbose:
            ip = packet[IP]
            proto, src_port, dst_port = get_packet_details(packet)

            print(
                f"[{proto}] {ip.src}:{src_port} -> "
                f"{ip.dst}:{dst_port} ({len(packet)} bytes)"
            )


# -----------------------------
# Verify access
# -----------------------------
def verify_access(interface=INTERFACE):
    try:
        sniff(
            iface=interface,
            filter=BPF_FILTER,
            count=1,
            timeout=3,
            store=False
        )
        print("Raw-socket/Admin access verified.")
        return True

    except PermissionError:
        print("Permission Error: Run VS Code as Administrator.")
        return False

    except Exception as e:
        print("Access check warning:", e)
        print("\nAvailable interfaces:")
        for iface in get_if_list():
            print(" -", iface)
        return False


# -----------------------------
# Start capture
# -----------------------------
def start_capture(interface=INTERFACE, verbose=True):
    print("Starting Stage 1 live packet capture...")
    print(f"Interface  : {interface}")
    print(f"BPF Filter : {BPF_FILTER}")
    print("Open browser or run: ping google.com")
    print("Press Ctrl + C to stop.\n")

    sniff(
        iface=interface,
        filter=BPF_FILTER,
        store=False,
        prn=lambda pkt: _packet_callback(pkt, verbose)
    )


# -----------------------------
# Main test
# -----------------------------
if __name__ == "__main__":
    print("IDS Stage 1 Packet Capture Test\n")

    if verify_access(INTERFACE):
        try:
            start_capture(INTERFACE, verbose=True)

        except KeyboardInterrupt:
            print("\nCapture stopped.")

            packets = packet_buffer.drain()
            print(f"Total packets drained: {len(packets)}")

            if packets and packets[0].haslayer(IP):
                print("Handoff OK: packet_buffer.drain() returned Scapy IP packets.")
            else:
                print("No IP packets captured.")