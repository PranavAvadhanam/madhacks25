"""
This module provides a PacketTranslator class to translate Scapy packets into
human-readable explanations.
"""
from typing import Dict, Any, Tuple
from scapy.all import TCP, UDP, ICMP

class PacketTranslator:
    def __init__(self):
        # 1. THE DICTIONARY: Mapping common ports to Human Concepts
        self.port_map = {
            # Web Traffic
            80:  {"service": "HTTP", "desc": "Unencrypted Web Traffic"},
            443: {"service": "HTTPS", "desc": "Secure Web Traffic"},
            8080: {"service": "HTTP-Alt", "desc": "Alternative Web Port"},
            
            # File & Command
            20: {"service": "FTP-Data", "desc": "Transferring Files (FTP)"},
            21: {"service": "FTP", "desc": "File Transfer Control"},
            22: {"service": "SSH", "desc": "Secure Remote Login"},
            23: {"service": "Telnet", "desc": "Insecure Remote Login"},
            
            # Email
            25: {"service": "SMTP", "desc": "Sending Email"},
            110: {"service": "POP3", "desc": "Receiving Email"},
            143: {"service": "IMAP", "desc": "Syncing Email"},
            
            # Infrastructure / Gaming / Misc
            53: {"service": "DNS", "desc": "Looking up IP addresses (Phonebook)"},
            67: {"service": "DHCP", "desc": "Requesting an IP address"},
            68: {"service": "DHCP", "desc": "Receiving an IP address"},
            123: {"service": "NTP", "desc": "Syncing Time"},
            3306: {"service": "MySQL", "desc": "Database Communication"},
            25565: {"service": "Minecraft", "desc": "Minecraft Server"},
        }

    def _analyze_tcp_flags(self, flags: str) -> Tuple[str, str]:
        """
        Translates cryptic flags (e.g., 'SA', 'F') into a narrative.
        Returns: (Short Type, Educational Explanation)
        """
        if 'R' in flags:
            return ("Connection Reset", "The connection was abruptly stopped (slammed shut). This usually happens if the service isn't running or a firewall blocked it.")
        if 'S' in flags and 'A' in flags:
            return ("Connection Accepted", "The server heard the knock and is opening the door (SYN-ACK).")
        if 'S' in flags:
            return ("Connection Request", "Attempting to start a conversation (Knocking on the door).")
        if 'F' in flags:
            return ("Connection Finished", "One side is done talking and is politely hanging up.")
        if 'P' in flags:
            return ("Data Push", "Sending actual data to the application immediately.")
        
        return ("Ongoing Communication", "Standard data transfer packet.")

    def translate(self, pkt: Any) -> Dict[str, Any]:
        """
        Takes a Scapy packet and returns a dictionary with 'friendly' fields.
        """
        friendly_data = {
            "service_name": "Unknown",
            "friendly_summary": "",
            "educational_data": ""
        }
        
        proto = None
        if pkt.haslayer(TCP):
            proto = "TCP"
        elif pkt.haslayer(UDP):
            proto = "UDP"
        elif pkt.haslayer(ICMP):
            proto = "ICMP"

        sport = pkt.sport if hasattr(pkt, 'sport') else None
        dport = pkt.dport if hasattr(pkt, 'dport') else None

        known_service = self.port_map.get(sport) or self.port_map.get(dport)
        
        if known_service:
            friendly_data['service_name'] = known_service['service']
            base_desc = known_service['desc']
        else:
            base_desc = f"Traffic on port {dport}"

        if proto == 'TCP':
            flags = pkt[TCP].flags
            flag_type, flag_explanation = self._analyze_tcp_flags(flags)
            
            friendly_data['friendly_summary'] = f"TCP {flag_type}: {base_desc}"
            friendly_data['educational_data'] = f"### Concept: TCP Flags\n* **{flag_type}:** {flag_explanation}\n\n### Service Context\n* **{base_desc}**"
            
        elif proto == 'UDP':
            friendly_data['friendly_summary'] = f"UDP Data: {base_desc}"
            friendly_data['educational_data'] = "### Concept: UDP\n* **User Datagram Protocol** is like sending a letter without a return receipt. \n* It's fast but doesn't guarantee arrival. \n* Used often for streaming, DNS, or online games."
            
        elif proto == 'ICMP':
            friendly_data['friendly_summary'] = "Ping / Network Diagnostic"
            friendly_data['educational_data'] = "### Concept: ICMP\n* **Internet Control Message Protocol**. \n* Usually used for 'Ping' to check if a computer is online."

        else:
            friendly_data['friendly_summary'] = f"{pkt.summary()}"
            friendly_data['educational_data'] = "No educational data available for this protocol yet."

        return friendly_data

# Instantiate the translator for use in the engine
packet_translator = PacketTranslator()

def get_packet_explanation(pkt: Any) -> Dict[str, Any]:
    return packet_translator.translate(pkt)