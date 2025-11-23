import asyncio
from datetime import datetime
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, DataTable, Input
from textual.containers import Container
from textual import on

from textual.widgets import Header, Footer, DataTable, Input, Log

from database import get_all_packets
from core.engine import main_engine as core_engine

class WireShrimpApp(App):
    """A Textual app for live packet sniffing."""

    CSS_PATH = "tui.css"
    BINDINGS = [
        ("d", "toggle_dark", "Toggle dark mode"),
        ("q", "quit", "Quit App"),
    ]

    # Define the columns for the DataTable
    PACKET_TABLE_COLUMNS = [
        "ID", "Time", "Src", "Dst", "Protocol", "Info"
    ]

    def __init__(self, interface: str | None = None):
        super().__init__()
        self.interface = interface
        self.is_sniffing = True # Start sniffing by default

    def compose(self) -> ComposeResult:
        """Create child widgets for the app."""
        yield Header()
        yield DataTable(id="packet_table")
        yield Log(id="log_panel", max_lines=200) # Visible log panel
        yield Input(placeholder="Enter command (e.g., stop, start, quit)", id="command_input")
        yield Footer()

    def on_mount(self) -> None:
        """Called when the app is mounted to the DOM."""
        table = self.query_one(DataTable)
        table.add_columns(*self.PACKET_TABLE_COLUMNS)
        # Start the background workers
        self.log_message("App mounted. Starting background workers...")
        self.update_table_worker = self.run_worker(self.update_packet_table, exclusive=False, name="TableUpdater")
        self.sniffer_worker = self.run_worker(self.run_sniffer, exclusive=False, name="Sniffer")
    
    def log_message(self, message: str) -> None:
        """Thread-safe method to write a message to the on-screen log."""
        log_panel = self.query_one(Log)
        log_panel.write_line(f"{datetime.now().strftime('%H:%M:%S')} | {message}")

    @on(Input.Submitted, "#command_input")
    async def handle_command(self, event: Input.Submitted) -> None:
        """Handle command input from the user."""
        command = event.value.lower().strip()
        self.query_one(Input).value = ""
        self.log_message(f"Command received: '{command}'")
        
        if command == "quit":
            self.sniffer_worker.cancel()
            self.exit()
        elif command == "stop":
            if self.is_sniffing:
                self.sniffer_worker.cancel()
                self.is_sniffing = False
                self.log_message("Packet sniffer stopped.")
        elif command == "start":
            if not self.is_sniffing:
                self.sniffer_worker = self.run_worker(self.run_sniffer, exclusive=True, name="Sniffer")
                self.is_sniffing = True
                self.log_message("Packet sniffer started.")
        else:
            self.log_message(f"Unknown command: '{command}'")

    async def run_sniffer(self) -> None:
        """Worker to run the core packet sniffing engine."""
        try:
            self.log_message("Sniffer worker started.")
            await core_engine(interface=self.interface)
        except asyncio.CancelledError:
            self.log_message("Sniffer worker cancelled by request.")
        except Exception as e:
            self.log_message(f"[ERROR] Sniffer worker failed: {e}")

    async def update_packet_table(self) -> None:
        """Periodically queries the database and redraws the entire table."""
        # Add a small initial delay to give the sniffer time to start up
        await asyncio.sleep(.3)
        
        display_limit = 1000
        while self.is_running:
            try:
                self.log_message("UI worker: Attempting to fetch packets...")
                # Run the synchronous DB call in a thread
                all_packets = await asyncio.to_thread(get_all_packets)
                self.log_message(f"UI worker: Fetched {len(all_packets)} packets.")
                
                # We want the most recent packets.
                # Get the last `display_limit` packets, then reverse to have newest first.
                packets_to_display = all_packets[-display_limit:][::-1]

                table = self.query_one(DataTable)

                # Preserve current scroll position and row count so we can
                # restore the user's viewport after updating the table.
                try:
                    old_row_count = table.row_count
                    old_scroll_y = int(table.scroll_y)
                except Exception:
                    old_row_count = 0
                    old_scroll_y = 0

                # Clear and update rows.
                table.clear()
                table.scroll_y = old_scroll_y
                rows = []
                # Compute available width for the table and reserve fixed widths
                # for the first columns so we can truncate the `Info` column to
                # avoid horizontal scrolling.
                try:
                    total_width = self.size.width
                except Exception:
                    # Fallback if size is not available in this context
                    total_width = 80

                # Fixed approximate widths for columns (characters)
                fixed_widths = {
                    "ID": 6,
                    "Time": 19,
                    "Src": 15,
                    "Dst": 15,
                    "Protocol": 8,
                }
                fixed_total = sum(fixed_widths.values()) + (len(self.PACKET_TABLE_COLUMNS) - 1) * 3
                # leave at least 10 chars for Info
                max_info = max(10, total_width - fixed_total)

                def truncate(text: str, limit: int) -> str:
                    if text is None:
                        return ""
                    s = str(text)
                    return s if len(s) <= limit else s[: max(0, limit - 1)] + "…"

                for pkt in packets_to_display:
                    info = truncate(pkt.summary, max_info)
                    src = truncate(pkt.source_ip, fixed_widths["Src"])
                    dst = truncate(pkt.destination_ip, fixed_widths["Dst"])
                    proto = truncate(pkt.protocol_type, fixed_widths["Protocol"])
                    rows.append((pkt.id, pkt.timestamp, src, dst, proto, info))
                
                if rows:
                    table.add_rows(rows)

                    # If the user was at the top before the update, keep
                    # auto-scrolling to show newest entries. Otherwise,
                    # restore their previous viewport by adjusting for the
                    # number of rows that were added at the top.
                    new_row_count = table.row_count
                    added = max(0, new_row_count - old_row_count)

                    if old_scroll_y <= 0:
                        # Auto-scroll to top (newest) when user is at top.
                        table.scroll_home(animate=False)
                    else:
                        # Keep the same content in view by scrolling to the
                        # row index shifted by the number of new rows.
                        try:
                            table.scroll_to(y=old_scroll_y + added, immediate=True)
                        except Exception:
                            # Fallback: don't change scroll if scroll_to fails.
                            pass

            except Exception as e:
                self.log_message(f"[ERROR] Failed to update table: {e}")

            # Wait before the next refresh
            await asyncio.sleep(.2)
    
    def action_quit(self) -> None:
        """An action to quit the app."""
        self.sniffer_worker.cancel()
        self.exit()
if __name__ == "__main__":
    app = WireShrimpApp()
    app.run()
