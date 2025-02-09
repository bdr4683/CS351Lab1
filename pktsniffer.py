import pyshark
import argparse

def ethernet_header(packet):
    print("Ethernet Header: ")
    print(f"\t-Packet Size: {packet.length}")
    print(f"\t-Source MAC Address: {packet.eth.src}")
    print(f"\t-Destination MAC Address: {packet.eth.dst}")
    print(f"\t-Ethertype: {packet.eth.type}")

def ip_header(packet):
    print("\nIP Header:")
    print(f"\t-Source IP: {packet.ip.src}")
    print(f"\t-Destination IP: {packet.ip.dst}")
    print(f"\t-Protocol: {packet.ip.proto}")

def tcp_header(packet):
    print("\nTCP Header:")
    print(f"\t-TCP Source Port: {packet.tcp.srcport}")
    print(f"\t-TCP Destination Port: {packet.tcp.dstport}")

def udp_header(packet):
    print("\nUDP Header:")
    print(f"\t-UDP Source Port: {packet.udp.srcport}")
    print(f"\t-UDP Destination Port: {packet.udp.dstport}")

def icmp_header(packet):
    print("\nICMP Header: ")
    print(f"ICMP Source Port: {packet.icmp.srcport}")
    print(f"ICMP Destination Port: {packet.icmp.dstport}")

def main():

    parser = argparse.ArgumentParser(description="Analyze a .pcap file.")
    parser.add_argument("-r", "--file", required=True, help="Path to the .pcap file")
    parser.add_argument("-c", "--count", type=int, help="Number of packets to process. Default 10000")
    parser.add_argument("host", "--host_address", type=str, help="Host IP address")
    parser.add_argument("port", "--port", type=str, help="Port number")

    args = parser.parse_args()

    max_packets = 10000
    if args.count:
        max_packets = args.count
    
    file = args.file
    
    capture = pyshark.FileCapture(file)

    count = 0

    for packet in capture:
        
        count += 1

        if count <= max_packets:

            print(f"Packet {packet.number}:\n")
            
            # Print ethernet header
            if 'ETH' in packet:
                ethernet_header(packet)
            
            # Print IP header
            if 'IP' in packet:
                ip_header(packet)
            
            # Encapsulated packets
            if 'TCP' in packet:
                tcp_header(packet)
            
            if 'UDP' in packet:
                udp_header(packet)

            if 'ICMP' in packet:
                icmp_header(packet)
            
            print("-" * 40)


if __name__ == "__main__":
    main()