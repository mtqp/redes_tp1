import sys
from scapy.all import *
from datetime import datetime, timedelta
from source import * 

message_source = source()

def add(message):
    message_source.add(message)
    if (message_source.count % 5000) == 0:
        print "Reached " + str(message_source.count) + " packets processed at: " + str(datetime.now().time())
        
def extract_arp_packet(packet):
    if packet.type == int(0x806):
        op_code = packet[ARP].op
        source = packet[ARP].psrc
        add((op_code, source))

def extract_for_graph_arp_packet(packet):
    if packet.type == int(0x806):
        op_code = packet[ARP].op
        source = packet[ARP].psrc
        destination = packet[ARP].pdst

        add((op_code, source, destination))
        
def extract_type_from_packet(packet):
    add(packet.type)
    
def type_key_parser(type):
    return hex(type)
    
def arp_key_parser(arp_key):
    return str(arp_key).replace("(","").replace(")","")
    
def sniff_types(source_file, statistics_file):
    header = "Type,Count"
    
    sniff(count = 170000, prn = extract_type_from_packet, offline = source_file)
    message_source.save(statistics_file, header, type_key_parser)
        
def sniff_arp(source_file, statistics_file):
    header = "OpCode,Source,Count"
    
    sniff(count = 170000, prn = extract_arp_packet, offline = source_file, filter="arp")
    message_source.save(statistics_file, header, arp_key_parser)

def sniff_graph(source_file, statistics_file):
    header = "OpCode,Source,Destination,Count"
    
    sniff(count = 170000, prn = extract_for_graph_arp_packet, offline = source_file, filter="arp")
    message_source.save(statistics_file, header, arp_key_parser)    
        
if (len(sys.argv) < 4):
    print 'Usage: python source_analizer.py [analysis source: type|arp|graph][source file][statistics file]'
else:
    analysis = sys.argv[1]
    source_file = sys.argv[2]
    statistics_file = sys.argv[3]
        
    if analysis == "type":
        sniff_types(source_file, statistics_file)
    elif analysis == "arp":
        sniff_arp(source_file, statistics_file)
    elif analysis == "graph":
        sniff_graph(source_file, statistics_file)
    else:
        print "This analyzer only creates statistics about types or arp traffic"

    
    