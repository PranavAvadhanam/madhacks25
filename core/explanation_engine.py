"""
This module provides a PacketTranslator class to translate Scapy packets into
human-readable explanations.
"""
from typing import Dict, Any, Tuple
from scapy.all import TCP, UDP, ICMP
import json

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

    def _analyze_tcp_flags(self, flags: str) -> Dict[str, str]:
        """
        Translates cryptic flags (e.g., 'SA', 'F') into a narrative.
        Returns: A dictionary with 'flag_type' and 'explanation'.
        """
        flag_info = {
            "flag_type": "Unknown",
            "explanation": "No specific flag information available."
        }
        
        if 'R' in flags:
            flag_info["flag_type"] = "RST (Reset)"
            flag_info["explanation"] = "The connection was abruptly stopped (slammed shut). This usually happens if the service isn't running, a firewall blocked it, or an error occurred. It's like hanging up the phone suddenly."
        elif 'S' in flags and 'A' in flags:
            flag_info["flag_type"] = "SYN-ACK (Synchronize-Acknowledge)"
            flag_info["explanation"] = "This is the server's response to a SYN packet, acknowledging the connection request and sending its own synchronization sequence number. It's the server saying 'I heard you, and I'm ready to talk too!'. This is the second step in the TCP 3-way handshake."
        elif 'S' in flags:
            flag_info["flag_type"] = "SYN (Synchronize)"
            flag_info["explanation"] = "This packet initiates a connection. A client sends a SYN to a server to start a conversation. It's like knocking on the door and saying 'Hello, can we talk?' This is the first step in the TCP 3-way handshake."
        elif 'F' in flags:
            flag_info["flag_type"] = "FIN (Finish)"
            flag_info["explanation"] = "One side is done talking and is politely requesting to close the connection. It's like saying 'Goodbye, I'm done with my part of the conversation.' This is part of the graceful connection termination process."
        elif 'P' in flags:
            flag_info["flag_type"] = "PSH (Push)"
            flag_info["explanation"] = "This flag tells the receiving application to immediately 'push' the buffered data to the application, without waiting for the buffer to fill up. It's like urging the post office to deliver this specific letter right now."
        elif 'A' in flags: # ACK without SYN or FIN
            flag_info["flag_type"] = "ACK (Acknowledge)"
            flag_info["explanation"] = "Confirms the receipt of data or a previous packet. It's like saying 'I got your message!'. ACKs are fundamental to TCP's reliability, ensuring data integrity."
        elif 'U' in flags:
            flag_info["flag_type"] = "URG (Urgent)"
            flag_info["explanation"] = "Indicates that some data within the segment is urgent and should be processed quickly. The urgent pointer field in the TCP header points to the last byte of urgent data. This flag is rarely used in modern networks."
        elif 'E' in flags:
            flag_info["flag_type"] = "ECE (ECN-Echo)"
            flag_info["explanation"] = "Part of Explicit Congestion Notification (ECN). It indicates that a TCP peer is ECN-capable during connection setup and that congestion has been experienced. It's a signal to slow down to prevent packet loss."
        elif 'C' in flags:
            flag_info["flag_type"] = "CWR (Congestion Window Reduced)"
            flag_info["explanation"] = "Part of Explicit Congestion Notification (ECN). It indicates that the sending host has reduced its congestion window in response to receiving an ECE flag. It's the sender acknowledging the 'slow down' signal."
        
        else:
            flag_info["flag_type"] = "Ongoing Communication"
            flag_info["explanation"] = "This packet is part of an established communication, typically carrying application data without special control signals. It's the main part of the conversation."
            
        return flag_info

    def translate(self, pkt: Any) -> Dict[str, Any]:
        """
        Takes a Scapy packet and returns a dictionary with 'friendly' fields.
        """
        friendly_data = {
            "service_name": "Unknown",
            "friendly_summary": "",
            "educational_data": {} # Initialize as a dictionary
        }
        
        proto = None
        protocol_description = ""
        packet_role_description = ""

        if pkt.haslayer(TCP):
            proto = "TCP"
            protocol_description = "Transmission Control Protocol (TCP) is a reliable, connection-oriented protocol. It ensures that data packets are delivered in order and without errors, managing retransmissions and flow control. Think of it as a phone call where both parties ensure the message is received correctly."
        elif pkt.haslayer(UDP):
            proto = "UDP"
            protocol_description = "User Datagram Protocol (UDP) is a faster, connectionless protocol. It does not guarantee delivery, order, or error checking, making it suitable for applications where speed is more critical than reliability, such as streaming video, online gaming, or DNS lookups. It's like sending a postcard – you send it, but don't check if it arrived."
        elif pkt.haslayer(ICMP):
            proto = "ICMP"
            protocol_description = "Internet Control Message Protocol (ICMP) is primarily used for diagnostic or error-reporting functions. It's not for transferring data between end systems, but for network devices to communicate operational information. Common uses include the 'ping' command to check host reachability. It's the network's way of sending status updates."

        sport = pkt.sport if hasattr(pkt, 'sport') else None
        dport = pkt.dport if hasattr(pkt, 'dport') else None

        known_service = self.port_map.get(sport) or self.port_map.get(dport)
        
        service_context = {
            "name": "Unknown",
            "port": dport if dport else sport, # Prefer destination port for service identification
            "description": "Traffic on an unknown or unmapped port. Could be a custom application, or encrypted traffic."
        }
        
        if known_service:
            friendly_data['service_name'] = known_service['service']
            service_context["name"] = known_service['service']
            service_context["description"] = known_service['desc']
            
        if proto == 'TCP':
            flags = str(pkt[TCP].flags)
            flag_info = self._analyze_tcp_flags(flags)
            
            friendly_data['friendly_summary'] = f"TCP {flag_info['flag_type']}: {service_context['name']}"
            packet_role_description = f"This TCP packet is primarily acting as a '{flag_info['flag_type'].split(' ')[0]}' signal. {flag_info['explanation']}"
            
            friendly_data['educational_data'] = {
                "protocol_overview": {
                    "name": proto,
                    "description": protocol_description
                },
                "packet_role": {
                    "type": flag_info['flag_type'],
                    "description": packet_role_description,
                    "flags": [{"flag": f, "meaning": self._analyze_tcp_flags(f)["explanation"]} for f in flags if f not in [' ']]
                },
                "service_context": service_context,
                "educational_tips": [
                    "TCP relies on a '3-way handshake' (SYN, SYN-ACK, ACK) to establish a connection. Look for these in sequence!",
                    "Unexpected RST packets can indicate connection issues, firewall blocks, or port scanning.",
                    "Many applications use TCP for reliable data transfer, such as web browsing (HTTP/S), email (SMTP, IMAP, POP3), and file transfer (FTP, SSH)."
                ]
            }
            
        elif proto == 'UDP':
            friendly_data['friendly_summary'] = f"UDP Data: {service_context['name']}"
            packet_role_description = f"This UDP packet is carrying data for the '{service_context['name']}' service. Since UDP is connectionless, this packet is sent without prior connection establishment or guarantees of delivery."
            
            friendly_data['educational_data'] = {
                "protocol_overview": {
                    "name": proto,
                    "description": protocol_description
                },
                "packet_role": {
                    "type": "Data Transfer",
                    "description": packet_role_description
                },
                "service_context": service_context,
                "educational_tips": [
                    "UDP is often used for real-time applications like video streaming, online gaming, and Voice over IP (VoIP) where occasional packet loss is acceptable for maintaining speed.",
                    "DNS (Domain Name System) queries typically use UDP for quick lookups of domain names to IP addresses.",
                    "Be aware that UDP can be used in denial-of-service (DoS) attacks due to its connectionless nature, where attackers can spoof source IPs more easily."
                ]
            }
            
        elif proto == 'ICMP':
            icmp_type = pkt[ICMP].type
            icmp_code = pkt[ICMP].code
            
            icmp_type_map = {
                0: "Echo Reply (Ping Response)",
                3: "Destination Unreachable",
                4: "Source Quench (Deprecated)",
                5: "Redirect",
                8: "Echo Request (Ping Request)",
                9: "Router Advertisement",
                10: "Router Solicitation",
                11: "Time Exceeded"
            }
            icmp_desc = icmp_type_map.get(icmp_type, f"Type {icmp_type}")

            friendly_data['friendly_summary'] = f"ICMP: {icmp_desc}"
            packet_role_description = f"This ICMP packet is a '{icmp_desc}'. ICMP packets are crucial for network diagnostics and error reporting, helping devices understand network conditions."

            friendly_data['educational_data'] = {
                "protocol_overview": {
                    "name": proto,
                    "description": protocol_description
                },
                "packet_role": {
                    "type": icmp_desc,
                    "description": packet_role_description,
                    "details": f"Type: {icmp_type}, Code: {icmp_code}"
                },
                "service_context": {
                    "name": "Network Management",
                    "description": "ICMP is integral to IP operations, providing diagnostic functions and reporting errors that occur during the delivery of IP datagrams. It doesn't use ports like TCP/UDP as it operates at the network layer."
                },
                "educational_tips": [
                    "The 'ping' command uses ICMP Echo Request and Echo Reply to test network connectivity and measure round-trip time.",
                    "ICMP 'Destination Unreachable' messages can indicate routing problems or firewall blocks.",
                    "Excessive ICMP traffic could be part of a network scan or a DoS attack (e.g., an ICMP flood)."
                ]
            }

        else:
            friendly_data['friendly_summary'] = f"{pkt.summary()}"
            friendly_data['educational_data'] = {
                "protocol_overview": {
                    "name": "Unknown/Other",
                    "description": "This packet uses a protocol that is not yet categorized or is part of a lower network layer."
                },
                "packet_role": {
                    "type": "Uncategorized",
                    "description": "This packet's specific role in the transaction is not currently identified by the translator."
                },
                "service_context": service_context,
                "educational_tips": [
                    "Investigating packets with unknown protocols can reveal unusual network activity or custom applications.",
                    "Consider if this packet is part of an ARP request, a spanning tree protocol message, or another non-IP layer protocol."
                ]
            }

        # Convert the educational_data dictionary to a JSON string
        friendly_data['educational_data'] = json.dumps(friendly_data['educational_data'], indent=2)

        return friendly_data

# Instantiate the translator for use in the engine
packet_translator = PacketTranslator()

def get_packet_explanation(pkt: Any) -> Dict[str, Any]:
    return packet_translator.translate(pkt)

# Instantiate the translator for use in the engine
packet_translator = PacketTranslator()

def get_packet_explanation(pkt: Any) -> Dict[str, Any]:
    return packet_translator.translate(pkt)