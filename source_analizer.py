import sys
from scapy.all import *
from source import * 

type_source = source()
arp_source = source()

def analize_arp_packet(packet):
    if packet.type == int(0x806):
        op_code = packet[ARP].op
        source = packet[ARP].psrc
        destination = packet[ARP].pdst
        arp_source.add_packet((op_code, source, destination))

def type_key_parser(type):
    return hex(type)
    
def arp_key_parser(arp_key):
    return str(arp_key).replace("(","").replace(")","")
    
def sniff_types(source_file, statistics_file):
    header = "Type,Count"
    
    sniff(prn = lambda pkt : type_source.add_packet(pkt.type), offline = source_file)
    type_source.save(statistics_file, header, type_key_parser)
        
def sniff_arp(source_file, statistics_file):
    header = "OpCode,Source,Destination,Count"
    
    sniff(prn = analize_arp_packet, offline = source_file, filter="arp")
    arp_source.save(statistics_file, header, arp_key_parser)

        
if (len(sys.argv) < 4):
    print 'Usage: python source_analizer.py [analysis source: type|arp][source file][statistics file]'
else:
    analysis = sys.argv[1]
    source_file = sys.argv[2]
    statistics_file = sys.argv[3]
        
    if analysis == "type":
        sniff_types(source_file, statistics_file)
    elif analysis == "arp":
        sniff_arp(source_file, statistics_file)
    else:
        print "This analyzer only creates statistics about types or arp traffic"

    
    