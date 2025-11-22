import asyncio
import socket
from typing import Dict, Any, List
from scapy.all import AsyncSniffer, Packet as ScapyPacket
from scapy.layers.inet import IP, TCP, UDP
from datetime import datetime
from database import bulk_insert_processed_packets_async, prune_database_async

# This will likely be a dataclass or a simple dictionary
Packet = Dict[str, Any]

def get_local_ip() -> str:
    """
    Determines the local IP address of the machine by connecting to a public
    DNS server. Returns '127.0.0.1' if the IP cannot be determined.
    """
    s = None
    try:
        # We don't need to actually connect, just create the socket and get its name
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # This is a non-blocking connect, it doesn't actually send data
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = '127.0.0.1' # Fallback
    finally:
        if s:
            s.close()
    return local_ip

def packet_callback(packet_queue: asyncio.Queue):
    """Callback function for scapy's sniffer. Puts captured packets into the queue."""
    def process_scapy_packet(pkt: ScapyPacket):
        packet_data = {
            "time": datetime.fromtimestamp(pkt.time).strftime('%Y-%m-%d %H:%M:%S.%f'),
            "length": len(pkt),
            "info": pkt.summary(),
            "src": None,
            "dst": None,
            "protocol": "UNKNOWN"
        }

        if pkt.haslayer(IP):
            packet_data["src"] = pkt[IP].src
            packet_data["dst"] = pkt[IP].dst
            
            if pkt.haslayer(TCP):
                packet_data["protocol"] = "TCP"
            elif pkt.haslayer(UDP):
                packet_data["protocol"] = "UDP"
            else:
                packet_data["protocol"] = "IP"

        try:
            packet_queue.put_nowait(packet_data)
        except asyncio.QueueFull:
            print("[Warning] Packet queue is full, dropping packet.")

    return process_scapy_packet

def process_packet(packet: Packet) -> Dict[str, Any]:
    """
    Processes a raw packet and prepares it for database insertion.
    This "dumbifies" the packet into the format expected by the DB model.
    """
    return {
        "timestamp": packet.get("time"),
        "source_ip": packet.get("src", "N/A"),
        "destination_ip": packet.get("dst", "N/A"),
        "protocol_type": packet.get("protocol"),
        "summary": packet.get("info"),
    }

async def process_and_store(packet_queue: asyncio.Queue):
    """
    Takes packets from the queue, processes them, and stores them in the database
    in batches using a robust and performant batching strategy.
    """
    batch = []
    BATCH_SIZE = 500  # Increased batch size
    FLUSH_INTERVAL = 0.5  # Flush at least once per second

    while True:
        try:
            # Wait for the first packet to arrive, with a timeout that ensures
            # the batch is flushed at least once per FLUSH_INTERVAL.
            packet = await asyncio.wait_for(packet_queue.get(), timeout=FLUSH_INTERVAL)
            batch.append(process_packet(packet))
            packet_queue.task_done()

            # Greedily fill the rest of the batch with any packets already in the queue
            while len(batch) < BATCH_SIZE:
                try:
                    packet = packet_queue.get_nowait()
                    batch.append(process_packet(packet))
                    packet_queue.task_done()
                except asyncio.QueueEmpty:
                    # The queue is empty, so we stop filling and proceed to flush.
                    break
            
            # If the batch is full, flush it immediately.
            if len(batch) >= BATCH_SIZE:
                await bulk_insert_processed_packets_async(batch)
                print(f"--- Flushed {len(batch)} packets to database (batch full). ---")
                batch = []

        except asyncio.TimeoutError:
            # The FLUSH_INTERVAL was reached. If there's anything in the
            # batch, flush it now.
            if batch:
                await bulk_insert_processed_packets_async(batch)
                print(f"--- Flushed {len(batch)} packets to database (timeout). ---")
                batch = []
        
        except Exception as e:
            print(f"[ERROR] An error occurred in the processing loop: {e}")
            # In case of an unknown error, wait a moment to prevent a tight error loop.
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
        except Exception as e:
            print(f"[ERROR] Periodic prune failed: {e}")

async def main_engine(interface: str = None):
    """
    The main engine that orchestrates sniffing, processing, and database maintenance.
    Handles graceful shutdown of all tasks.
    """
    packet_queue = asyncio.Queue(maxsize=10000) # Large queue for bursty traffic
    db_capacity = 10000
    
    # Determine local IP to create a filter
    local_ip = get_local_ip()
    bpf_filter = f"host {local_ip}"
    
    print(f"Sniffer started on interface: {interface or 'default'}")
    print(f"Applying BPF filter to capture traffic for host: {local_ip}")
    
    sniffer = AsyncSniffer(
        iface=interface,
        prn=packet_callback(packet_queue),
        store=False,
        filter=bpf_filter,
    )
    
    sniffer.start()
    
    # Create and manage all background tasks
    processor_task = asyncio.create_task(process_and_store(packet_queue))
    pruner_task = asyncio.create_task(periodic_pruner(interval_seconds=30, limit=db_capacity))
    
    tasks = [processor_task, pruner_task]

    try:
        # This will wait for any of the tasks to complete or fail.
        # Since they run forever, it effectively waits until cancellation.
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        print("\nReceived stop signal.")
    finally:
        # On shutdown, cancel all managed tasks
        for task in tasks:
            task.cancel()
        # Wait for them to finish their cancellation logic
        await asyncio.gather(*tasks, return_exceptions=True)

        # Flush any remaining packets in the queue
        print("Flushing remaining packets...")
        final_batch = []
        while not packet_queue.empty():
            final_batch.append(process_packet(packet_queue.get_nowait()))
        if final_batch:
            try:
                # Use the synchronous version here as the event loop may be closing
                from database import bulk_insert_processed_packets
                bulk_insert_processed_packets(final_batch)
                print(f"--- Flushed final {len(final_batch)} packets to database. ---")
            except Exception as e:
                print(f"[ERROR] Failed to flush final batch: {e}")

        print("Stopping sniffer...")
        sniffer.stop()
        await asyncio.sleep(0.5)
        print("Sniffer stopped.")

if __name__ == "__main__":
    from database import init_db
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
