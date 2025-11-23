import asyncio
from typing import Dict, Any
from scapy.all import AsyncSniffer, IP, IPv6, TCP, UDP

# This will likely be a dataclass or a simple dictionary
Packet = Dict[str, Any]

# Buffer storage fallback for when DB is unavailable
PACKET_STORE: list[Dict[str, Any]] = []

# Try to import async bulk insert from database module
_db_enabled = False
_db_bulk_async = None
try:
    from database.db import bulk_insert_processed_packets_async, init_db  # type: ignore

    try:
        init_db()
        _db_bulk_async = bulk_insert_processed_packets_async
        _db_enabled = True
        print("Database batch inserter available; DB batching enabled.")
    except Exception as e:
        print(f"Warning: DB init failed ({e}); falling back to in-memory buffer.")
        _db_enabled = False
except Exception:
    _db_enabled = False


def _extract_packet_fields(pkt) -> Dict[str, Any]:
    """Try to extract common fields from a Scapy packet in a robust way."""
    # timestamp
    ts = getattr(pkt, "time", None)

    # source/destination: prefer IP/IPv6 layers when present
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

    # protocol determination
    proto = None
    if TCP in pkt:
        proto = "TCP"
    elif UDP in pkt:
        proto = "UDP"
    elif IP in pkt:
        proto = str(pkt[IP].proto)
    else:
        proto = pkt.name if hasattr(pkt, "name") else None

    # length and summary
    length = len(pkt) if pkt is not None else 0
    try:
        info = pkt.summary()
    except Exception:
        info = str(pkt)

    return {
        "time": ts,
        "src": src,
        "dst": dst,
        "protocol": proto,
        "length": length,
        "info": info,
    }


async def start_sniffing(interface: str, packet_queue: asyncio.Queue):
    """
    Start a Scapy AsyncSniffer that puts simplified packet dicts into an
    asyncio.Queue without blocking the event loop.
    """
    print(f"Starting packet sniffer on interface: {interface}")
    loop = asyncio.get_running_loop()
    packet_id = 0

    def _on_packet(pkt):
        # This callback runs in the sniffer's thread; push safely to asyncio loop
        nonlocal packet_id
        packet_id += 1
        fields = _extract_packet_fields(pkt)
        packet_data = {"id": packet_id, **fields}
        # Use call_soon_threadsafe because scapy will call this from another thread
        loop.call_soon_threadsafe(packet_queue.put_nowait, packet_data)
        # Also log a simple line to the console (thread-safe print is ok)
        print(f"[{interface}] Captured packet {packet_id}: {packet_data['protocol']} {packet_data['src']}->{packet_data['dst']}")

    sniffer = AsyncSniffer(iface=interface if interface else None, prn=_on_packet, store=False, promisc=False)
    sniffer.start()

    try:
        # Run forever; sniffer runs in background.
        while True:
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        pass
    finally:
        sniffer.stop()


def process_packet(packet: Packet) -> Dict[str, Any]:
    """
    Processes a raw packet dict to make it digestible for the use case.
    """
    print(f"Dumbifying packet ID: {packet.get('id')}")
    processed_packet = {
        "source_ip": packet.get("src"),
        "destination_ip": packet.get("dst"),
        "protocol_type": packet.get("protocol"),
        "summary": packet.get("info"),
        "timestamp": packet.get("time"),
        "length": packet.get("length"),
        "id": packet.get("id"),
    }
    return processed_packet


async def process_and_store(packet_queue: asyncio.Queue):
    """
    Takes packets from the queue, processes them, and stores them.
    """
    print("Starting packet processor and storer.")
    # Buffering configuration
    BUFFER_MAX = 100
    FLUSH_INTERVAL = 5.0  # seconds

    buffer: list[Dict[str, Any]] = []
    timer_task: asyncio.Task | None = None

    async def _flush_buffer():
        nonlocal buffer
        if not buffer:
            return
        batch = buffer
        buffer = []

        if _db_enabled and _db_bulk_async is not None:
            try:
                # call the async bulk insert
                await _db_bulk_async(batch)
            except Exception as e:
                print(f"DB bulk insert failed: {e}; falling back to in-memory storage.")
                PACKET_STORE.extend(batch)
        else:
            # fallback: keep packets in memory
            PACKET_STORE.extend(batch)

    async def _timer_flush():
        try:
            await asyncio.sleep(FLUSH_INTERVAL)
            await _flush_buffer()
        except asyncio.CancelledError:
            # Timer cancelled because we flushed early
            return

    try:
        while True:
            raw_packet = await packet_queue.get()
            print(f"Processing and storing packet ID: {raw_packet.get('id')}")
            processed_packet = process_packet(raw_packet)

            buffer.append(processed_packet)

            # start timer when first item arrives
            if len(buffer) == 1 and (timer_task is None or timer_task.done()):
                timer_task = asyncio.create_task(_timer_flush())

            # flush immediately when we hit buffer size
            if len(buffer) >= BUFFER_MAX:
                # cancel timer and flush
                if timer_task is not None and not timer_task.done():
                    timer_task.cancel()
                    try:
                        await timer_task
                    except Exception:
                        pass
                    timer_task = None
                await _flush_buffer()

            print(f"Buffered packet (buffer size={len(buffer)})")
            packet_queue.task_done()
    finally:
        # Ensure any remaining buffered packets are flushed on shutdown
        if timer_task is not None and not timer_task.done():
            timer_task.cancel()
            try:
                await timer_task
            except Exception:
                pass
        await _flush_buffer()
        print("Processor shutting down; flushed remaining packets.")



async def main_engine(interface: str | None = None):
    """
    The main engine that orchestrates the sniffing and processing.
    """
    packet_queue = asyncio.Queue()
    sniffer_task = asyncio.create_task(start_sniffing(interface, packet_queue))
    processor_task = asyncio.create_task(process_and_store(packet_queue))

    try:
        await asyncio.gather(sniffer_task, processor_task)
    except asyncio.CancelledError:
        print("Shutting down engine")


if __name__ == "__main__":
    # Example usage: choose an interface string appropriate to your OS.
    # On Windows this is often something like 'Ethernet' or 'Wi-Fi'.
    import sys

    iface = None
    if len(sys.argv) > 1:
        iface = sys.argv[1]

    try:
        asyncio.run(main_engine(interface=iface))
    except KeyboardInterrupt:
        print("Engine stopped.")
