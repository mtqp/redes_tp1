#! /usr/bin/env python
import sys
#import datetime
from datetime import datetime, timedelta
from scapy.all import *

packets = []


def listen_for(amount_of_minutes):
    log_timeout = (datetime.now() + timedelta(minutes = amount_of_minutes)).time()
    print "this will end at: " + str(log_timeout)
    sniff(prn = lambda pkt : packets.append(pkt), timeout = amount_of_minutes * 60)
    wrpcap("a_beverly.cap",packets)    
    print "done bitch!"



if (len(sys.argv) == 1):
    print 'Usage: python passive_listener.py [listening time in minutes]' # [OPTIONAL: name of dump]'
else:
    minutes = int(sys.argv[1])
    listen_for(minutes)
