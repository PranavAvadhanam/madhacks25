import asyncio
from datetime import datetime
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, DataTable, Input, Markdown, LoadingIndicator
from textual.containers import Container
from textual import on
import json




# Assumed imports based on your snippet
from database import get_all_packets, get_packet_by_id
from core.engine import main_engine as core_engine




class WireShrimpApp(App):
  """A Textual app for live packet sniffing."""




  ENABLE_COMMAND_PALETTE = False
  FRIENDLY_STATE = False




  CSS_PATH = "tui.css"
  BINDINGS = [
      ("q", "quit", "Quit App"),
      ("escape", "hide_details", "Hide Detail View"),
  ]

  ADJECTIVE_CACHE = [
    "Swift", "Bright", "Noble", "Strong", "Wise", 
    "Bold", "Clever", "Keen", "Brave", "Quick",
    "Radiant", "Mighty", "Graceful", "Vibrant", "Stellar",
    "Brilliant", "Valiant", "Daring", "Nimble", "Fearless",
    "Gleaming", "Majestic", "Spirited", "Lively", "Dazzling",
    "Gallant", "Intrepid", "Zealous", "Glorious", "Luminous",
    "Serene", "Tranquil", "Peaceful", "Calm", "Gentle",
    "Cheerful", "Joyful", "Merry", "Sunny", "Happy",
    "Elegant", "Refined", "Polished", "Pristine", "Pure",
    "Loyal", "True", "Faithful", "Steadfast", "Devoted",
    "Astute", "Witty", "Sharp", "Savvy", "Canny",
    "Cosmic", "Mystic", "Ancient", "Eternal", "Timeless",
    "Golden", "Silver", "Crystal", "Diamond", "Emerald",
    "Thunder", "Lightning", "Storm", "Blaze", "Frost",
    "Azure", "Crimson", "Amber", "Jade", "Onyx"
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
      self.initial_table_loaded = False




  def compose(self) -> ComposeResult:
      """Create child widgets for the app."""
      yield Header()
      yield DataTable(id="packet_table")
      with Container(id="detail_view", classes="hidden"):
          yield Markdown(id="detail_content")
      yield LoadingIndicator(id="table_loader")
      # Updated placeholder to include filter command
      yield Input(placeholder="Commands: e.g. start, stop, help, quit", id="command_input")
      yield Footer()




  def on_mount(self) -> None:
      """Called when the app is mounted to the DOM."""
      self.theme = "gruvbox"
      table = self.query_one(DataTable)
      table.add_columns(*self.PACKET_TABLE_COLUMNS)
      # Start with the table hidden and loader visible until first rows arrive
      try:
       loader = self.query_one("#table_loader")
       table.add_class("hidden")
       loader.remove_class("hidden")
      except Exception:
       pass
    
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
          content += f"**Friendly Source Name:** {packet.friendly_src}\n"
          content += f"**Friendly Destination Name:** {packet.friendly_dst}\n"
          content += f"**Timestamp:** {packet.timestamp}\n"
          content += f"**Source:** {packet.source_ip}\n"
          content += f"**Destination:** {packet.destination_ip}\n"
          content += f"**Protocol:** {packet.protocol_type}\n"
          content += f"**Service:** {packet.service_name}\n\n"
        
          # --- Start of JSON parsing and formatting for educational_data ---
          try:
              educational_data = json.loads(packet.educational_data)
            
              content += "### Educational Explanation\n"
            
              # Protocol Overview
              if "protocol_overview" in educational_data:
                  po = educational_data["protocol_overview"]
                  content += f"#### Protocol: {po.get('name', 'N/A')}\n"
                  content += f"{po.get('description', 'No description available.')}\n\n"
                
              # Packet Role
              if "packet_role" in educational_data:
                  pr = educational_data["packet_role"]
                  content += f"#### Packet Role: {pr.get('type', 'N/A')}\n"
                  content += f"{pr.get('description', 'No specific role identified.')}\n"
                  if "details" in pr:
                      content += f"Details: {pr['details']}\n"
                  if "flags" in pr and pr["flags"]:
                      content += "\n##### TCP Flags:\n"
                      for flag_item in pr["flags"]:
                          content += f"* **{flag_item.get('flag', '')}:** {flag_item.get('meaning', '')}\n"
                  content += "\n"
                    
              # Service Context
              if "service_context" in educational_data:
                  sc = educational_data["service_context"]
                  content += f"#### Service Context: {sc.get('name', 'N/A')}\n"
                  content += f"Port: {sc.get('port', 'N/A')}\n"
                  content += f"{sc.get('description', 'No service context available.')}\n\n"
                
              # Educational Tips
              if "educational_tips" in educational_data and educational_data["educational_tips"]:
                  content += "#### Educational Tips:\n"
                  for tip in educational_data["educational_tips"]:
                      content += f"* {tip}\n"
            
          except json.JSONDecodeError:
              content += f"### Explanation (Error parsing educational data):\n{packet.educational_data}\n"
          # --- End of JSON parsing and formatting for educational_data ---
        
          detail_content.update(content)
          detail_view_container.border_title = "Packet Info"
          detail_view_container.remove_class("hidden")
          detail_view_container.add_class("visible")
          detail_view_container.focus()
      else:
          print(f"Packet with ID {packet_id} not found.")
  def action_hide_details(self):
      """Hide the detail view."""
      self.screen.remove_class("dimmed")
      detail_view_container = self.query_one("#detail_view")
      detail_view_container.border_title = ""
      detail_view_container.remove_class("visible")
      detail_view_container.add_class("hidden")




  async def show_help_details(self):
      """Generate and show help information in the detail view."""
      detail_view_container = self.query_one("#detail_view")
      detail_content = self.query_one("#detail_content", Markdown)
    
      self.screen.add_class("dimmed")
    
      help_text = "## Available Commands\n\n"
      help_text += "*   **`quit`**: Exit the application.\n"
      help_text += "*   **`stop`**: Stop the packet sniffing process.\n"
      help_text += "*   **`start`**: Start the packet sniffing process if it was stopped.\n"
      help_text += "*   **`friend`**: Toggle friendly mode. When active, it displays friendly names for IP addresses (e.g., 'Bucky' for 142.250.190.14).\n"
      help_text += "*   **`qw`** or **`quitwindow`**: Hide the currently open detail view (e.g., 'Packet Info' or 'Help Information').\n"
      help_text += "*   **`filter <protocol>`**: Filter the displayed packets by a specific protocol (e.g., `filter tcp`, `filter udp`, `filter icmp`).\n"
      help_text += "*   **`filter <IP_address>`**: Filter packets by a specific source or destination IP address (e.g., `filter 192.168.1.1`, `filter 10.0.0.5`).\n"
      help_text += "*   **`filter <friendly_adjective>`**: Filter packets by a specific source or destination friendly name (e.g., `filter Dazzling` or `filter dazzling` for \"Dazzling Badger\").\n"
      help_text += "*   **`filter clear`**: Clear any active packet filter, displaying all captured packets.\n"
      help_text += "*   **`view <id>`**: Open a detailed view for a specific packet, identified by its unique ID in the table.\n"
      help_text += "*   **`help`**: Display this help information.\n"
      help_text += "\n### Keyboard Shortcuts\n\n"
      help_text += "*   **`q`**: Immediately quit the application.\n"
      help_text += "*   **`escape`**: Hide the current detail view (e.g., 'Packet Info' or 'Help Information').\n"








      detail_content.update(help_text)
      detail_view_container.border_title = "Guide"
      detail_view_container.remove_class("hidden")
      detail_view_container.add_class("visible")
      detail_view_container.focus()




  @on(Input.Submitted, "#command_input")
  async def handle_command(self, event: Input.Submitted) -> None:
      """Handle command input from the user."""
      command_parts = event.value.strip().lower().split()
      if not command_parts:
          return
        
      command = command_parts[0]
      self.query_one(Input).value = ""
      print(f"Command received: '{command}'")
    
      if command_parts[0] == "quit" or (len(command_parts) == 1 and command_parts[0] == "q"):
         self.sniffer_worker.cancel()
         self.exit()

    


      elif command == "stop":
          if self.is_sniffing:
              self.sniffer_worker.cancel()
              self.is_sniffing = False
              self.notify("Packet sniffer stopped.")




      elif command == "friend":
          if self.FRIENDLY_STATE:
              self.notify("Friendly mode deactivated :|")
              self.FRIENDLY_STATE = False
          else:
              self.notify("Friendly mode activated :)")
              self.FRIENDLY_STATE = True
    




      elif command == "start":
          if not self.is_sniffing:
              self.sniffer_worker = self.run_worker(self.run_sniffer, exclusive=False, name="Sniffer")
              self.is_sniffing = True
              self.notify("Packet sniffer started.")








      elif command == "qw" or command == "quitwindow":
          self.action_hide_details()








      elif command == "filter":
          # Handle 'filter clear' or 'filter <protocol>' or filter <friendly adjective>
          if len(command_parts) > 1:
              arg = command_parts[1]
              if arg == "clear":
                  self.current_filter = None
                  self.notify("Filter cleared.")
              elif "." in arg or "/" in arg:
                  self.notify("Filtering for IP: " + arg)
                  self.current_filter = arg
              elif arg[0].upper()+arg[1:] in self.ADJECTIVE_CACHE:
                  self.notify("Filtering for friend: " + arg[0].upper()+arg[1:] + " " + "Badger")
                  self.current_filter = arg[0].upper()+arg[1:] + " " + "Badger"
              else:
                  self.current_filter = arg
                  self.notify(f"Filtering for protocol: {arg.upper()}")
          else:
              self.notify("Usage: filter <protocol> OR filter clear OR filter <friend adjective>")








      elif command == "view":
          if len(command_parts) > 1 and command_parts[1].isdigit():
              packet_id = int(command_parts[1])
              await self.show_packet_details(packet_id)
          else:
              self.notify("Usage: view <packet_id>")




      elif command == "help":
          await self.show_help_details()
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
      await asyncio.sleep(0.3)
    
      display_limit = 1000
      while self.is_running:
          try:
              # Run the synchronous DB call in a thread
              all_packets = await asyncio.to_thread(get_all_packets)
            
              # --- FILTERING LOGIC ---
              if self.current_filter:
                  if "." in self.current_filter or "/" in self.current_filter:
                      # IP Filtering
                      filtered_packets = [
                          p for p in all_packets
                          if p.source_ip == self.current_filter or p.destination_ip == self.current_filter
                      ]
                      self.sub_title = f"Filter: {self.current_filter} ({len(filtered_packets)} pkts)"
                  if " Badger" in self.current_filter:
                      # Friendly filtering
                      filtered_packets = [
                          p for p in all_packets
                          if p.friendly_src == self.current_filter or p.friendly_dst == self.current_filter
                      ]
                      self.sub_title = f"Filter: {self.current_filter} ({len(filtered_packets)} pkts)"
                  else:
                      # Protocol Filtering
                      filtered_packets = [
                          p for p in all_packets
                          if p.protocol_type and self.current_filter.lower() in p.protocol_type.lower()
                      ]
                      self.sub_title = f"Filter: {self.current_filter.upper()} ({len(filtered_packets)} pkts)"
                
                  # Apply limit after filtering
                  packets_to_display = filtered_packets[-display_limit:][::-1]
              else:
                  self.sub_title = "Live Capture"
                  packets_to_display = all_packets[-display_limit:][::-1]
              # -----------------------




              table = self.query_one(DataTable)




              # Preserve current scroll position
              old_scroll_y = int(table.scroll_y)
              old_scroll_x = int(table.scroll_x)
            
              # Capture current state to decide on auto-scroll
              is_at_top = old_scroll_y == 0




              # Clear and update rows.
              table.clear()
            
              rows = []
            
              try:
                  total_width = self.size.width
              except Exception:
                  total_width = 80




              # Fixed approximate widths for columns (characters)
              fixed_widths = {
                  "ID": 6, "Time": 19, "Src": 15, "Dst": 15,
                  "Protocol": 8, "Service": 10, "Direction": 10,
              }
              fixed_total = sum(fixed_widths.values()) + (len(self.PACKET_TABLE_COLUMNS) - 1) * 3
              max_summary = max(40, total_width - fixed_total)




              def truncate(text: str, limit: int) -> str:
                  if text is None: return ""
                  s = str(text)
                  return s if len(s) <= limit else s[: max(0, limit - 1)] + "…"




              # Protocol color mapping
              protocol_colors = {
                  "ARP": "#83C092", "UDP": "#DBBC7F",
                  "ICMP": "#E67E80", "TCP": "#7FBBB3", "DNS": "#D699B6"
              }




              for pkt in packets_to_display:
                  time_ago = ""
                  if pkt.timestamp:
                      delta = datetime.now() - pkt.timestamp
                      time_ago = f"{int(delta.total_seconds())}s ago"
                
                  summary = truncate(pkt.friendly_summary, max_summary)
                  src = truncate(pkt.source_ip, fixed_widths["Src"])
                  dst = truncate(pkt.destination_ip, fixed_widths["Dst"])
                
                  if self.FRIENDLY_STATE:
                      src = truncate(pkt.friendly_src, fixed_widths["Src"])
                      dst = truncate(pkt.friendly_dst, fixed_widths["Dst"])
                
                  # --- FIX START: Define proto_text before using it ---
                  # Ensure we handle NoneTypes gracefully
                  proto_raw = pkt.protocol_type if pkt.protocol_type else "N/A"
                
                  color = protocol_colors.get(proto_raw.upper(), "#83C092")
                  colored_proto = f"[{color}]{truncate(proto_raw, fixed_widths['Protocol'])}[/]"
                  # --- FIX END ---




                  service = truncate(pkt.service_name, fixed_widths["Service"])
                  direction = truncate(pkt.traffic_direction, fixed_widths["Direction"])
                
                  # Add row with key=pkt.id to help Textual track items if you switch to differential updates later
                  rows.append((str(pkt.id), time_ago, src, dst, colored_proto, service, direction, summary))
            
              if rows:
                  table.add_rows(rows)
                  # On first successful row population, hide the loader and reveal the table
                  if not self.initial_table_loaded:
                   try:
                       loader = self.query_one("#table_loader")
                       loader.add_class("hidden")
                       table.remove_class("hidden")
                   except Exception:
                       pass
                   self.initial_table_loaded = True




                  # Logic to maintain scroll position
                  if is_at_top:
                      # If user was at the top, keep them at the top (newest items)
                      table.scroll_to(x=old_scroll_x, y=0, animate=False)
                  else:
                      # If user was scrolled down, try to keep them there
                      # Note: Because we cleared the table, strict index restoration is tricky.
                      # This simply puts them back to the same visual offset.
                      table.scroll_to(x=old_scroll_x, y=old_scroll_y, animate=False)




          except Exception as e:
              # Use self.notify so you can see errors in the UI
              # self.notify(f"Table Update Error: {e}", severity="error")
              print(f"[ERROR] Failed to update table: {e}")




          # Wait before the next refresh
          await asyncio.sleep(0.5) # Increased slightly to reduce flickering
    
  def action_quit(self) -> None:
      """An action to quit the app."""
      self.sniffer_worker.cancel()
      self.exit()




if __name__ == "__main__":
  app = WireShrimpApp()
  app.run()