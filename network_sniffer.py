import socket
import scapy.all as scapy
from struct import unpack

def packet_handler(packet):
    src_mac = packet.src
    dst_mac = packet.dst

    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        payload = packet[scapy.Raw].load if packet.haslayer(scapy.Raw) else ''

        # Print basic packet information
        print(f"Source MAC: {src_mac}, Destination MAC: {dst_mac}, Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}, Payload Length: {len(payload)}")

        # Interpret payload based on protocol
        if protocol == 6:  # TCP protocol
            if packet.haslayer(scapy.TCP):
                src_port = packet[scapy.TCP].sport
                dst_port = packet[scapy.TCP].dport
                if dst_port == 80 or src_port == 80:  # HTTP traffic usually uses port 80
                    http_payload = payload.decode('utf-8', errors='ignore')
                    # Now you can work with the HTTP payload
                    print("HTTP Payload:", http_payload)

        elif protocol == 17:  # UDP protocol
            if packet.haslayer(scapy.UDP):
                src_port = packet[scapy.UDP].sport
                dst_port = packet[scapy.UDP].dport
                # Interpret UDP payload based on specific applications
                pass  # Add your UDP payload interpretation code here

        # Add interpretation for other protocols as needed

# Set the network interface for capturing packets
scapy.conf.iface = 'wlan0'

# Set a callback function to handle captured packets
scapy.sniff(prn=packet_handler, store=0)
