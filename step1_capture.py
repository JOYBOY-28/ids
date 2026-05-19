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
import sys


# -----------------------------
# Key Variables
# -----------------------------
# Auto-detect suitable interface
def get_default_interface():
    """Auto-detect the first available network interface"""
    try:
        available = get_if_list()
        print(f"[DEBUG] get_if_list() returned: {available}")
        
        # Filter out loopback and disconnected interfaces
        non_loopback = [iface for iface in available if iface.lower() not in ['lo', 'lo0']]
        print(f"[DEBUG] Non-loopback interfaces: {non_loopback}")
        
        if non_loopback:
            selected = non_loopback[0]
            print(f"[DEBUG] Selected interface: {selected}")
            return selected
        elif available:
            selected = available[0]
            print(f"[DEBUG] Selected (fallback): {selected}")
            return selected
        else:
            print("[DEBUG] No interfaces found, using fallback 'Ethernet'")
            return "Ethernet"
    except Exception as e:
        print(f"[DEBUG] Error in get_default_interface(): {e}")
        return "Ethernet"


INTERFACE = get_default_interface()
print(f"[DEBUG] INTERFACE set to: {INTERFACE}\n")
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
    print(f"[DEBUG] verify_access() called with interface: {interface}")
    try:
        print(f"[DEBUG] Attempting sniff on {interface} with BPF filter '{BPF_FILTER}' for 3 seconds...")
        sniff(
            iface=interface,
            filter=BPF_FILTER,
            count=1,
            timeout=3,
            store=False
        )
        print("[OK] Raw-socket/Admin access verified.")
        return True

    except PermissionError as e:
        print(f"[ERROR] Permission Error: {e}")
        print("   Run VS Code or terminal as Administrator.")
        return False

    except Exception as e:
        print(f"[ERROR] Interface '{interface}' error: {type(e).__name__}: {e}")
        print("\n[INFO] Available interfaces on your system:")
        try:
            available = get_if_list()
            print(f"[DEBUG] get_if_list() returned: {available}")
            for iface in available:
                print(f"  - {iface}")
            
            if available:
                print(f"\n[TIP] Try changing INTERFACE to one of the above (e.g., '{available[0]}')")
        except Exception as e2:
            print(f"[DEBUG] Error listing interfaces: {e2}")
        return False


# -----------------------------
# Start capture
# -----------------------------
def start_capture(interface=INTERFACE, verbose=True):
    print("\n" + "="*60)
    print("Starting Stage 1: Live Packet Capture...")
    print("="*60)
    print(f"Interface  : {interface}")
    print(f"BPF Filter : {BPF_FILTER}")
    print(f"Max Packets: {MAX_PACKETS}")
    print("\nTo generate traffic:")
    print("  - Open a browser and visit a website")
    print("  - Or run: ping google.com")
    print("\nPress Ctrl + C to stop.\n")

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
    print("="*60)
    print("IDS Stage 1: Packet Capture Test")
    print("="*60)
    print(f"[DEBUG] Module INTERFACE: {INTERFACE}\n")

    print("[DEBUG] Calling verify_access()...")
    if verify_access(INTERFACE):
        print("[DEBUG] Access verified, starting capture...\n")
        try:
            start_capture(INTERFACE, verbose=True)

        except KeyboardInterrupt:
            print("\n[OK] Capture stopped.")

            packets = packet_buffer.drain()
            print(f"Total packets drained: {len(packets)}")

            if packets and packets[0].haslayer(IP):
                print("Handoff OK: packet_buffer.drain() returned Scapy IP packets.")
            else:
                print("No IP packets captured.")
    else:
        print("[DEBUG] Access verification failed. Exiting.")