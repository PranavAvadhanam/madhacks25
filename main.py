import asyncio
import sys
import os
from core import main_engine
from database import init_db, get_all_packets

# The name of the database file
DB_FILE = "packets.db"

async def main():
    """
    Main asynchronous routine for the application.
    Initializes DB, creates and manages the main application task.
    """
    # --- IMPORTANT ---
    # Set the network interface to use for sniffing here.
    # On macOS/Linux, you can find your interface name by running `ifconfig` or `ip a`
    # in your terminal. Common names are 'en0' (for Wi-Fi/Ethernet on macOS),
    # 'eth0', or 'wlan0' (on Linux).
    #
    # Set this to None to let scapy try and pick a default.
    INTERFACE_TO_USE = "en0" # <-- CHANGE THIS to your actual interface

    # Initialize the database and create tables
    init_db()
    print("Database initialized.")

    try:
        # Create the main task for the packet engine, passing the interface
        main_task = asyncio.create_task(main_engine(interface=INTERFACE_TO_USE))
        await main_task
    except asyncio.CancelledError:
        # This is expected during a graceful shutdown.
        print("Main application task was cancelled.")

if __name__ == "__main__":
    # This is the main entry point for the application.
    # It sets up the asyncio event loop and handles graceful shutdown on Ctrl+C.
    
    # You MUST run this with sudo, e.g., `sudo python3 main.py`
    
    # Clean up previous database file for a fresh run
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
        print(f"Removed existing database file: {DB_FILE}")

    print("Starting the packet analysis tool...")
    print("Press Ctrl+C to stop.")

    try:
        asyncio.run(main())
    except PermissionError:
        print("\n[ERROR] Permission denied to access network interface.")
        print("Please try running the script with administrator privileges (e.g., using 'sudo').")
        sys.exit(1)
    except KeyboardInterrupt:
        # This is the primary mechanism for stopping the application.
        # asyncio.run() automatically handles the cancellation of running tasks.
        print("\nApplication stopped by user. Shutting down gracefully...")
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")
    finally:
        # This block will run after the asyncio loop is closed
        print("\n--- Captured Packets Summary ---")
        if not os.path.exists(DB_FILE):
            print("Database file not found. No packets were likely stored.")
        else:
            try:
                all_packets = get_all_packets()
                if not all_packets:
                    print("No packets were stored in the database.")
                else:
                    print(f"Total packets captured: {len(all_packets)}")
                    # Print details for the first 10 packets as a sample
                    for packet in all_packets[:10]:
                        print(
                            f"  - ID: {packet.id}, Time: {packet.timestamp}, "
                            f"Src: {packet.source_ip}, Dst: {packet.destination_ip}, "
                            f"Proto: {packet.protocol_type}, Info: {packet.summary}"
                        )
                    if len(all_packets) > 10:
                        print(f"  ... and {len(all_packets) - 10} more.")
            except Exception as e:
                print(f"Error reading from database: {e}")
        print("---------------------------------")
