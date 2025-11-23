import asyncio
from datetime import datetime
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, DataTable, Input, Markdown
from textual.containers import Container
from textual import on

# Assumed imports based on your snippet
from database import get_all_packets, get_packet_by_id
from core.engine import main_engine as core_engine

class WireShrimpApp(App):
    """A Textual app for live packet sniffing."""

    ENABLE_COMMAND_PALETTE = False

    CSS_PATH = "tui.css"
    BINDINGS = [
        ("d", "toggle_dark", "Toggle dark mode"),
        ("q", "quit", "Quit App"),
        ("escape", "hide_details", "Hide Detail View"),
    ]

    # Define the columns for the DataTable
    PACKET_TABLE_COLUMNS = [
        "ID", "Time", "Src", "Dst", "Protocol", "Service", "Direction", "Summary"
    ]

    def __init__(self, interface: str | None = None):
        super().__init__()
        self.interface = interface
        self.is_sniffing = True  # Start sniffing by default
        self.current_filter: str | None = None  # Store the active filter

    def compose(self) -> ComposeResult:
        """Create child widgets for the app."""
        yield Header()
        yield DataTable(id="packet_table")
        with Container(id="detail_view", classes="hidden"):
            yield Markdown(id="detail_content")
        # Updated placeholder to include filter command
        yield Input(placeholder="Commands: filter <proto>, filter clear, stop, start, view <id>", id="command_input")
        yield Footer()

    def on_mount(self) -> None:
        """Called when the app is mounted to the DOM."""
        self.theme = "gruvbox"
        table = self.query_one(DataTable)
        table.add_columns(*self.PACKET_TABLE_COLUMNS)
        
        # Start the background workers
        print("App mounted. Starting background workers...")
        self.update_table_worker = self.run_worker(self.update_packet_table, exclusive=False, name="TableUpdater")
        self.sniffer_worker = self.run_worker(self.run_sniffer, exclusive=False, name="Sniffer")
    
    async def show_packet_details(self, packet_id: int):
        """Fetch packet details and show them."""
        packet = await asyncio.to_thread(get_packet_by_id, packet_id)
        detail_view_container = self.query_one("#detail_view")
        detail_content = self.query_one("#detail_content", Markdown)
        if packet:
            self.screen.add_class("dimmed")
            content = f"## Packet ID: {packet.id}\n\n"
            content += f"**Timestamp:** {packet.timestamp}\n"
            content += f"**Source:** {packet.source_ip}\n"
            content += f"**Destination:** {packet.destination_ip}\n"
            content += f"**Protocol:** {packet.protocol_type}\n"
            content += f"**Service:** {packet.service_name}\n\n"
            content += f"### Explanation\n{packet.educational_data}"
            
            detail_content.update(content)
            detail_view_container.remove_class("hidden")
            detail_view_container.add_class("visible")
            detail_view_container.focus()
        else:
            print(f"Packet with ID {packet_id} not found.")

    def action_hide_details(self):
        """Hide the detail view."""
        self.screen.remove_class("dimmed")
        detail_view_container = self.query_one("#detail_view")
        detail_view_container.remove_class("visible")
        detail_view_container.add_class("hidden")

    @on(Input.Submitted, "#command_input")
    async def handle_command(self, event: Input.Submitted) -> None:
        """Handle command input from the user."""
        command_parts = event.value.strip().lower().split()
        if not command_parts:
            return
            
        command = command_parts[0]
        self.query_one(Input).value = ""
        print(f"Command received: '{command}'")
        
        if command == "quit":
            self.sniffer_worker.cancel()
            self.exit()

        elif command == "stop":
            if self.is_sniffing:
                self.sniffer_worker.cancel()
                self.is_sniffing = False

        elif command == "start":
            if not self.is_sniffing:
                self.sniffer_worker = self.run_worker(self.run_sniffer, exclusive=False, name="Sniffer")
                self.is_sniffing = True

        elif command == "filter":
            # Handle 'filter clear' or 'filter <protocol>'
            if len(command_parts) > 1:
                arg = command_parts[1]
                if arg == "clear":
                    self.current_filter = None
                    self.notify("Filter cleared.")
                else:
                    self.current_filter = arg
                    self.notify(f"Filtering for protocol: {arg.upper()}")
            else:
                self.notify("Usage: filter <protocol> OR filter clear")

        elif command == "view":
            if len(command_parts) > 1 and command_parts[1].isdigit():
                packet_id = int(command_parts[1])
                await self.show_packet_details(packet_id)
            else:
                self.notify("Usage: view <packet_id>")
        else:
            self.notify(f"Unknown command: '{command}'")

    async def run_sniffer(self) -> None:
        """Worker to run the core packet sniffing engine."""
        try:
            await core_engine(interface=self.interface)
        except asyncio.CancelledError:
            pass  # This is expected when stopping the sniffer
        except Exception as e:
            print(f"[ERROR] Sniffer worker failed: {e}")

    async def update_packet_table(self) -> None:
        """Periodically queries the database and redraws the entire table."""
        # Add a small initial delay to give the sniffer time to start up
        await asyncio.sleep(.3)
        
        display_limit = 1000
        while self.is_running:
            try:
                # Run the synchronous DB call in a thread
                all_packets = await asyncio.to_thread(get_all_packets)
                
                # --- FILTERING LOGIC ---
                # Filter packets BEFORE slicing if a filter is active
                if self.current_filter:
                    filtered_packets = [
                        p for p in all_packets 
                        if p.protocol_type and self.current_filter.lower() in p.protocol_type.lower()
                    ]
                    # Update the header sub-title to show filter status
                    self.sub_title = f"Filter: {self.current_filter.upper()} ({len(filtered_packets)} pkts)"
                    packets_to_display = filtered_packets[-display_limit:][::-1]
                else:
                    self.sub_title = "Live Capture"
                    packets_to_display = all_packets[-display_limit:][::-1]
                # -----------------------

                table = self.query_one(DataTable)

                # Preserve current scroll position and row count
                try:
                    old_row_count = table.row_count
                    old_scroll_y = int(table.scroll_y)
                    old_scroll_x = int(table.scroll_x)
                except Exception:
                    old_row_count = 0
                    old_scroll_y = 0

                # Clear and update rows.
                table.clear()
                table.scroll_y = old_scroll_y
                rows = []
                
                try:
                    total_width = self.size.width
                except Exception:
                    total_width = 80

                # Fixed approximate widths for columns (characters)
                fixed_widths = {
                    "ID": 6,
                    "Time": 19,
                    "Src": 15,
                    "Dst": 15,
                    "Protocol": 8,
                    "Service": 10,
                    "Direction": 10,
                }
                fixed_total = sum(fixed_widths.values()) + (len(self.PACKET_TABLE_COLUMNS) - 1) * 3
                # leave at least 10 chars for Summary
                max_summary = max(40, total_width - fixed_total)

                def truncate(text: str, limit: int) -> str:
                    if text is None:
                        return ""
                    s = str(text)
                    return s if len(s) <= limit else s[: max(0, limit - 1)] + "…"

                for pkt in packets_to_display:
                    time_ago = ""
                    if pkt.timestamp:
                        delta = datetime.now() - pkt.timestamp
                        time_ago = f"{int(delta.total_seconds())}s ago"
                    
                    summary = truncate(pkt.friendly_summary, max_summary)
                    src = truncate(pkt.source_ip, fixed_widths["Src"])
                    dst = truncate(pkt.destination_ip, fixed_widths["Dst"])
                    proto = truncate(pkt.protocol_type, fixed_widths["Protocol"])
                    service = truncate(pkt.service_name, fixed_widths["Service"])
                    direction = truncate(pkt.traffic_direction, fixed_widths["Direction"])
                    rows.append((pkt.id, time_ago, src, dst, proto, service, direction, summary))
                
                if rows:
                    table.add_rows(rows)

                    new_row_count = table.row_count
                    # Logic to maintain scroll position specifically for live updating lists
                    if old_scroll_y <= 0:
                        # Auto-scroll to top (newest) when user is at top.
                        table.scroll_home(x=old_scroll_x, y=0, animate=False)
                    else:
                        # Attempt to stabilize view
                        added = max(0, new_row_count - old_row_count)
                        try:
                            table.scroll_to(old_scroll_x, y=old_scroll_y + added, immediate=True, animate=False)
                        except Exception:
                            pass

            except Exception as e:
                print(f"[ERROR] Failed to update table: {e}")

            # Wait before the next refresh
            await asyncio.sleep(.2)
    
    def action_quit(self) -> None:
        """An action to quit the app."""
        self.sniffer_worker.cancel()
        self.exit()

if __name__ == "__main__":
    app = WireShrimpApp()
    app.run()
