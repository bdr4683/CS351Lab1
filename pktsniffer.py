import pyshark

capture = pyshark.FileCapture('packetcap.pcap')

for packet in capture:
    print(packet)