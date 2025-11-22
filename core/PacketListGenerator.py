from scapy.all import sniff, get_if_list, get_if_addr, conf
import socket

# Show what we're working with
print("=== DIAGNOSTICS ===")
print(f"Interfaces: {get_if_list()}")
print(f"Default interface: {conf.iface}")
print(f"Interface IP: {get_if_addr(conf.iface)}")

# Get real IP
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
my_ip = s.getsockname()[0]
s.close()
print(f"Outbound IP: {my_ip}")


packet_list = []

def handle_packet(pkt):
    packet_list.append(pkt)
    print(f"[{len(packet_list)}] {pkt.summary()}")

sniff(filter=f"host {my_ip}", prn=handle_packet, count=50, promisc=False)

# After capture, packet_list contains everything
print(f"\nCaptured {len(packet_list)} packets")


