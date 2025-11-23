import sys
import os
import click
from ui.tui import WireShrimpApp
from database import init_db, get_all_packets

# The name of the database file
DB_FILE = "packets.db"

@click.group()
def cli():
    """WireShrimp CLI application for network packet analysis."""
    pass

@cli.command()
@click.option(
    "--interface",
    "-i",
    default=None,
    help="Network interface to sniff on (e.g., 'en0', 'eth0', 'wlan0'). "
         "If not specified, scapy will attempt to find a default."
)
def run(interface):
    """
    Run the WireShrimp interactive Textual UI application.
    You MUST run this with sudo: `sudo python3 main.py run`
    """
    # Clean up previous database file for a fresh run
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
        print(f"Removed existing database file: {DB_FILE}")

    # Initialize the database and create tables
    init_db()
    print("Database initialized.")

    print("Starting the WireShrimp application...")
    print("Press Ctrl+C or 'q' to quit the app.")

    try:
        app = WireShrimpApp()
        # Pass the interface to the app. This will be handled in WireShrimpApp.
        app.interface = interface 
        app.run()
    except PermissionError:
        print("\n[ERROR] Permission denied to access network interface.")
        print("Please try running the command with administrator privileges (e.g., using 'sudo').")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] An unexpected error occurred: {e}")
        sys.exit(1)
    finally:
        # This block will run after the Textual app exits
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
                print(f"[ERROR] Error reading from database: {e}")
        print("---------------------------------")

if __name__ == "__main__":
    cli()
