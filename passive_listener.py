#! /usr/bin/env python
import sys
from datetime import datetime, timedelta
from scapy.all import *

packets = []

def log_packet(pkt):
    packets.append(pkt)
    if (len(packets) % 1000) == 0:
        print "Reached " + str(len(packets)) + " packets logged at: " + str(datetime.now().time())


def listen_for(amount_of_minutes, dump_name):
    log_timeout = (datetime.now() + timedelta(minutes = amount_of_minutes)).time()
    dump_name = dump_name + ".cap"
    
    print "---------------------------"
    print "I will be listening up to: " + str(log_timeout)
    
    sniff(prn = log_packet, timeout = amount_of_minutes * 60)
    wrpcap(dump_name, packets)    
    
    print "---------------------------"
    print "Dump saved as: " + dump_name + " containing " + len(packets) + " packets"



if (len(sys.argv) < 3):
    print 'Usage: python passive_listener.py [listening time in minutes][name of dump]'
else:
    minutes = int(sys.argv[1])
    dump_name = sys.argv[2]
    listen_for(minutes, dump_name)
