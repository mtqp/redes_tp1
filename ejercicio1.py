#! /usr/bin/env python
from scapy.all import *

def arp_monitor_callback(pkt):
    if ARP in pkt and pkt[ARP].op in (1,2): #who-has or is-at
        return pkt.sprintf("%ARP.hwsrc% %ARP.psrc%")

sniff(prn=arp_monitor_callback, filter="arp", store=0)

#sniff(prn = lambda x : x.summary())
#sniff(prn = lambda x : x.summary(), filter="arp")

#hagamos frula frula frula
