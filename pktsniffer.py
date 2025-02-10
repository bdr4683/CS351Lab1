import pyshark
import argparse

##############################################
#       Data Comm & Networking HW 1          #
#         Author: Brandon Ranallo            #
##############################################

# Print ethernet header
def ethernet_header(packet):
    print("Ethernet Header: ")
    print(f"\t-Packet Size: {packet.length}")
    print(f"\t-Source MAC Address: {packet.eth.src}")
    print(f"\t-Destination MAC Address: {packet.eth.dst}")
    print(f"\t-Ethertype: {packet.eth.type}")

# Print IP header
def ip_header(packet):
    print("\nIP Header:")
    print(f"\t-Source IP: {packet.ip.src}")
    print(f"\t-Destination IP: {packet.ip.dst}")
    print(f"\t-Protocol: {packet.ip.proto}")

# Print TCP header
def tcp_header(packet):
    print("\nTCP Header:")
    print(f"\t-TCP Source Port: {packet.tcp.srcport}")
    print(f"\t-TCP Destination Port: {packet.tcp.dstport}")

# Print UDP header
def udp_header(packet):
    print("\nUDP Header:")
    print(f"\t-UDP Source Port: {packet.udp.srcport}")
    print(f"\t-UDP Destination Port: {packet.udp.dstport}")

# Print ICMP header
def icmp_header(packet):
    print("\nICMP Header: ")
    print(f"ICMP Source Port: {packet.icmp.srcport}")
    print(f"ICMP Destination Port: {packet.icmp.dstport}")

# Create the display filter to be passed into Pyshark file capture
def packet_filter(args) -> str:

    filter_string = []

    if args.host:
        filter_string.append(f"ip.host == {args.host}")
    if args.port:
        filter_string.append(f"tcp.port == {args.port}")
    if args.ip:
        filter_string.append("ip")
    if args.tcp:
        filter_string.append("tcp")
    if args.udp:
        filter_string.append("udp")
    if args.icmp:
        filter_string.append("icmp")

    connector = ' and '

    return connector.join(filter_string)
    

def main():

    parser = argparse.ArgumentParser(description="Analyze a .pcap file.")
    parser.add_argument("-r", "--file", required=True, help="Path to the .pcap file")
    parser.add_argument("-c", "--count", type=int, help="Number of packets to process. Default 10000")
    parser.add_argument("--host", help="Host IP address")
    parser.add_argument("--port", help="Port number")
    parser.add_argument("--ip", action="store_true", help="Filter IP protocol")
    parser.add_argument("--tcp", action="store_true", help="Filter TCP protocol")
    parser.add_argument("--udp", action="store_true", help="Filter UDP protocol")
    parser.add_argument("--icmp", action="store_true", help="Filter ICMP protocol")


    args = parser.parse_args()

    

    max_packets = 10000
    if args.count:
        max_packets = args.count

    disp_filter = packet_filter(args)
    
    file = args.file
    capture = pyshark.FileCapture(file, display_filter=disp_filter)

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