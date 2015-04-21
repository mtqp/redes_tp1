import sys
#from datetime import datetime, timedelta
from scapy.all import *

#packets_count = 0
type_source = dict()

def analize_packet(packet):
    #packets_count += 1
    packet_type = packet.type
    if type_source.has_key(packet_type):
        type_source[packet_type] += 1
    else:
        type_source[packet_type] = 1

if (len(sys.argv) < 3):
    print 'Usage: python source_analizer.py [source file][statistics file]'
else:
    source_file = sys.argv[1]
    statistics_file = sys.argv[2]

    sniff(prn = analize_packet, offline = source_file)

    all_types = type_source.keys()
    all_types.sort()

    csv = open(statistics_file,"w")
    csv.write("Type,Count\n")
    for type in all_types:
        csv.write(hex(type) + "," + str(type_source[type]) + "\n")
    csv.close()

