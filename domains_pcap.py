import sys
from scapy.all import *
from scapy.utils import RawPcapReader
from scapy.layers.dns import DNS, DNSQR

lerpcap = str(sys.argv[1])
dns_packets = rdpcap(lerpcap)
for packet in dns_packets:
    if packet.haslayer(DNS):
        qname = packet[DNSQR].qname
        print("IP src", packet.src, "IP dst", packet.dst, qname)
