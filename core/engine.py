import asyncio
import socket
from datetime import datetime
from typing import Dict, Any
from scapy.all import AsyncSniffer
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from database.db import bulk_insert_processed_packets_async, prune_database_async
from core.explanation_engine import get_packet_explanation

Packet = Dict[str, Any]
knownIps = []

# Mapping of IP protocol numbers to their string representations
IP_PROTOCOL_MAP = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    89: "OSPF",
    132: "SCTP",
}


def _extract_packet_fields(pkt) -> Dict[str, Any]:
    ts = getattr(pkt, "time", None)
    if ts is not None:
        ts = datetime.fromtimestamp(ts)

    src = dst = None
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
    elif IPv6 in pkt:
        src = pkt[IPv6].src
        dst = pkt[IPv6].dst
    else:
        src = getattr(pkt, "src", None)
        dst = getattr(pkt, "dst", None)

    local_ip = get_local_ip()
    traffic_direction = "Upload" if src == local_ip else "Download"

    # Detect starting layer
    first_layer = pkt.firstlayer().name
    if first_layer == "IP":
        link_type = "IP"
    elif first_layer == "IPv6":
        link_type = "IPv6"
    else:
        link_type = "Ether"

    proto = None
    if TCP in pkt:
        proto = "TCP"
    elif UDP in pkt:
        proto = "UDP"
    elif IP in pkt:
        proto_num = pkt[IP].proto
        proto = IP_PROTOCOL_MAP.get(proto_num, str(proto_num))
    else:
        proto = pkt.name if hasattr(pkt, "name") else None

    length = len(pkt) if pkt is not None else 0

    explanation = get_packet_explanation(pkt)

    return {
        "time": ts,
        "src": src,
        "dst": dst,
        "protocol": proto,
        "length": length,
        "raw_packet": bytes(pkt),
        "link_type": link_type,
        "service_name": explanation["service_name"],
        "traffic_direction": traffic_direction,
        "friendly_summary": explanation["friendly_summary"],
        "educational_data": explanation["educational_data"],
    }


def get_local_ip() -> str:
    """Get the local IP address by creating a dummy connection."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def packet_callback(packet_queue: asyncio.Queue, loop: asyncio.AbstractEventLoop):
    """Create a callback function for the sniffer."""
    packet_id = 0
    dropped_count = 0

    def _on_packet(pkt):
        nonlocal packet_id, dropped_count
        packet_id += 1
        fields = _extract_packet_fields(pkt)
        packet_data = {"id": packet_id, **fields}

        if packet_queue.qsize() >= packet_queue.maxsize:
            dropped_count += 1
            if dropped_count % 100 == 1:
                print(f"[WARN] Queue full, dropped {dropped_count} packets so far")
            return

        loop.call_soon_threadsafe(packet_queue.put_nowait, packet_data)

    return _on_packet


def process_packet(packet: Packet) -> Dict[str, Any]:
    return {
        "source_ip": packet.get("src"),
        "destination_ip": packet.get("dst"),
        "protocol_type": packet.get("protocol"),
        "raw_packet": packet.get("raw_packet"),
        "link_type": packet.get("link_type"),
        "timestamp": packet.get("time"),
        "service_name": packet.get("service_name"),
        "traffic_direction": packet.get("traffic_direction"),
        "friendly_summary": packet.get("friendly_summary"),
        "educational_data": packet.get("educational_data"),
    }


async def process_and_store(packet_queue: asyncio.Queue):
    """
    Takes packets from the queue, processes them, and stores them in the database
    in batches using a robust and performant batching strategy.
    """
    batch = []
    BATCH_SIZE = 100
    FLUSH_INTERVAL = 0.1

    while True:
        try:
            packet = await asyncio.wait_for(packet_queue.get(), timeout=FLUSH_INTERVAL)
            batch.append(process_packet(packet))
            packet_queue.task_done()

            while len(batch) < BATCH_SIZE:
                try:
                    packet = packet_queue.get_nowait()
                    batch.append(process_packet(packet))
                    packet_queue.task_done()
                except asyncio.QueueEmpty:
                    break

            if len(batch) >= BATCH_SIZE:
                await bulk_insert_processed_packets_async(batch)
                print(f"--- Flushed {len(batch)} packets to database (batch full). ---")
                batch = []

        except asyncio.TimeoutError:
            if batch:
                await bulk_insert_processed_packets_async(batch)
                print(f"--- Flushed {len(batch)} packets to database (timeout). ---")
                #print(batch)
                batch = []

        except asyncio.CancelledError:
            if batch:
                await bulk_insert_processed_packets_async(batch)
                print(f"--- Flushed {len(batch)} packets to database (cancelled). ---")
            raise

        except Exception as e:
            print(f"[ERROR] An error occurred in the processing loop: {e}")
            await asyncio.sleep(1)


async def periodic_pruner(interval_seconds: int, limit: int):
    """
    A background task that periodically wakes up and prunes the database
    to keep it within the specified row limit.
    """
    while True:
        await asyncio.sleep(interval_seconds)
        try:
            print("--- Running periodic database prune check... ---")
            await prune_database_async(limit=limit)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            print(f"[ERROR] Periodic prune failed: {e}")


async def main_engine(interface: str | None = None):
    """The main engine that orchestrates sniffing, processing, and database maintenance."""
    packet_queue = asyncio.Queue(maxsize=10000)
    db_capacity = 10000
    loop = asyncio.get_running_loop()

    local_ip = get_local_ip()
    bpf_filter = f"host {local_ip}"

    sniffer = AsyncSniffer(
        iface=interface,
        prn=packet_callback(packet_queue, loop),
        store=False,
        filter=bpf_filter,
    )

    sniffer.start()

    processor_task = asyncio.create_task(process_and_store(packet_queue))
    pruner_task = asyncio.create_task(periodic_pruner(interval_seconds=30, limit=db_capacity))

    tasks = [processor_task, pruner_task]

    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        # This is expected when the sniffer is stopped.
        pass
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        sniffer.stop()



if __name__ == "__main__":
    from database.db import init_db
    init_db()

    async def run_wrapper():
        try:
            await main_engine()
        except asyncio.CancelledError:
            print("Main engine task cancelled.")

    loop = asyncio.get_event_loop()
    main_task = loop.create_task(run_wrapper())

    try:
        print("Starting packet sniffing engine... Press Ctrl+C to stop.")
        loop.run_until_complete(main_task)
    except KeyboardInterrupt:
        print("\nCtrl+C detected, initiating shutdown...")
        main_task.cancel()
        loop.run_until_complete(main_task)
    finally:
        loop.close()
        print("Engine shut down successfully.")
