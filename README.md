# CS351Lab1

To run the program, use

    python pktsniffer.py -r <pcap file>

Optional arguments:

    -c <number of packets>      
        -Specifies a max number of packets to display

    --host <host IP>            
        -Specifies a host IP to filter by
    
    --port <port #>
        -Specifies a port number to filter by
    
    --ip
        -Filter by IP protocol
    
    --tcp
        -Filter by TCP protocol
    
    --udp
        -Filter by UDP protocol
    
    --icmp
        -filter by ICMP protocol

Example:

    Filter by host IP and TCP protocol, limit to 10 results
    python pktsniffer.py -r packetcap.pcap -c 10 --host 142.250.72.106
