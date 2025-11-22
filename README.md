# madhacks25 (WireShrimp ?)

**Team:** Connor, Jack, Niyati, Pranav

## The Problem: The Wireshark Learning Curve

Wireshark is the industry standard for network protocol analysis, offering immense power and detail. However, for students, aspiring developers, and junior engineers, its interface can be overwhelming. The sheer volume of "raw" data, complex filtering syntax, and the presumed knowledge of networking concepts create a steep learning curve, making it difficult to gain initial insights into network traffic.

## Our Solution: A Stepping Stone to Network Analysis

We are building a Command-Line Interface (CLI) tool that serves as a "stepping stone" to more advanced tools like Wireshark. By adding a layer of abstraction, our tool will provide a user-friendly way to capture, analyze, and understand network traffic. The goal is to make network analysis more accessible and intuitive for those new to the field, fostering a better understanding of fundamental networking concepts.

## Key Features

*   **Live Packet Capture:** Easily start and stop capturing packets on a selected network interface.
*   **Simplified Packet View:** Instead of a raw data dump, packets are presented in a clean, human-readable summary, highlighting the most important information (IP addresses, ports, protocols).
*   **User-Friendly Filtering:** Apply simple, intuitive filters based on common criteria like IP address, port number, or protocol (e.g., `http`, `dns`, `tcp`).
*   **Real-Time Statistics:** View a live dashboard of basic network statistics, such as total packets captured, protocol distribution (e.g., 60% TCP, 30% UDP, 10% Other), and top conversations.
*   **Conversation View:** Group packets into conversations (e.g., a complete TCP handshake and data transfer) to understand the flow of communication between two hosts.
*   **Educational Mode:** An interactive "Packet Explainer" that allows users to select a packet and get a clear explanation of its different headers and fields (e.g., "This is the source IP address...").

## Target Audience

*   Computer Science Students
*   Aspiring Software & Network Engineers
*   Cybersecurity Beginners
*   Anyone curious about the data flowing through their network!
