from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import datetime

class NetworkSniffer:
    def __init__(self):
        # Tracking network statistics
        self.packet_count = 0
        self.protocol_stats = defaultdict(int)
        self.ip_connections = defaultdict(set)
        self.start_time = datetime.datetime.now()

    def packet_callback(self, packet):
        # Increment total packet count
        self.packet_count += 1

        # Check if packet has IP layer
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Track IP connections
            self.ip_connections[src_ip].add(dst_ip)

            # Protocol analysis
            if TCP in packet:
                self.protocol_stats['TCP'] += 1
            elif UDP in packet:
                self.protocol_stats['UDP'] += 1
            else:
                self.protocol_stats['Other'] += 1

    def start_sniffing(self, interface='eth0', packet_count=100):
        """
        Start network sniffing on the specified interface
        
        Args:
            interface (str): Network interface to sniff (default 'eth0')
            packet_count (int): Number of packets to capture
        """
        print(f"Starting network sniffing on {interface}...")
        sniff(iface=interface, prn=self.packet_callback, count=packet_count)
        self.generate_report()

    def generate_report(self):
        """Generate a summary report of network traffic"""
        end_time = datetime.datetime.now()
        duration = end_time - self.start_time

        print("\n--- Network Traffic Report ---")
        print(f"Total Packets Captured: {self.packet_count}")
        print(f"Capture Duration: {duration}")
        
        print("\nProtocol Distribution:")
        for protocol, count in self.protocol_stats.items():
            percentage = (count / self.packet_count) * 100
            print(f"{protocol}: {count} packets ({percentage:.2f}%)")
        
        print("\nUnique IP Connections:")
        for src_ip, destinations in self.ip_connections.items():
            print(f"{src_ip} connected to: {', '.join(destinations)}")

def main():
    sniffer = NetworkSniffer()
    sniffer.start_sniffing(interface='eth0', packet_count=50)

if __name__ == '__main__':
    main()
