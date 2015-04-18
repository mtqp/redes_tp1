#! /usr/bin/env python
from scapy.all import *

def packetPrinter(pkt):
    return pkt.show() #.summary()

sniff(prn = packetPrinter, filter="arp")
#sniff(prn = lambda x : x.summary(), filter="arp")

#levanta un archivo pcap --> lo generamos con el wireshark y dsp se levanta
#>>> a=rdpcap("myArchivo.pcap")
#>>> a

#hagamos frula frula frula
