import sys
#from datetime import datetime, timedelta
from scapy.all import *

#packets_count = 0
type_source = dict()
arp_source = dict()

#hay codigo repetido que podriamos refactorizar!
def analize_packet_type(packet):
    #packets_count += 1
    packet_type = packet.type
    if type_source.has_key(packet_type):
        type_source[packet_type] += 1
    else:
        type_source[packet_type] = 1

#hay codigo repetido que podriamos refactorizar!
def analize_arp_packet(packet):
    if packet.type == int(0x806):
        #packet.show()
        op_code = packet[ARP].op
        source = packet[ARP].psrc
        destination = packet[ARP].pdst
        key = (op_code, source, destination)
        if arp_source.has_key(key):
            arp_source[key] += 1
        else:
            arp_source[key] = 1    
        
#hay codigo repetido que podriamos refactorizar!        
def save_types_as_csv(file, types):
    csv = open(file,"w")
    csv.write("Type,Count\n")
    for type in types:
        csv.write(hex(type) + "," + str(type_source[type]) + "\n")
    csv.close()

def save_arps_as_csv(file, arp_keys):
    csv = open(file,"w")
    csv.write("OpCode,Source,Destination,Count\n")
    for arp_key in arp_keys:
        parsedKey = str(arp_key).replace("(","").replace(")","")
        csv.write(parsedKey + "," + str(arp_source[arp_key]) + "\n")
    csv.close()
    
#hay codigo repetido que podriamos refactorizar!
def sniff_types(source_file, statistics_file):
    sniff(prn = analize_packet_type, offline = source_file)

    all_types = type_source.keys()
    all_types.sort()

    save_types_as_csv(statistics_file, all_types)
    
#hay codigo repetido que podriamos refactorizar!
def sniff_arp(source_file, statistics_file):
    sniff(prn = analize_arp_packet, offline = source_file, filter="arp")

    all_arps = arp_source.keys()
    all_arps.sort()
    
    save_arps_as_csv(statistics_file, all_arps)
    
    #do smth with the keys maybe and then save it up (there's a way to override
    #the str function and prettyprint the fuck outta it
        
if (len(sys.argv) < 4):
    print 'Usage: python source_analizer.py [analysis source: type|arp][source file][statistics file]'
else:
    analysis = sys.argv[1]
    source_file = sys.argv[2]
    statistics_file = sys.argv[3]
        
    #parametrizar estoo con funciones!
    if analysis == "type":
        sniff_types(source_file, statistics_file)
    elif analysis == "arp":
        sniff_arp(source_file, statistics_file)
    else:
        print "This analyzer only creates statistics about types or arp traffic"

    
    