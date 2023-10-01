#! /usr/bin/env python2.7
from scapy.all import *
from netfilterqueue import NetfilterQueue

def modify(packet):
    
    #converts the raw packet to a scapy compatible string
    icmp_packet = IP(packet.get_payload())
    # get_payload() function is for getting the whole packet,
    # Nothing to do with the payload itself, same for set_payload() 
    rdp_packet = IP(bytes(icmp_packet[ICMP].payload))
    
    #modify the packet all you want here
    packet.set_payload(bytes(rdp_packet))
    
    # The printing is just for Debugging reasons, can be deleted.
    print('ICMP Packet: ')
    print(icmp_packet.show())
    print('RDP Packet: ')
    print(rdp_packet.show())
  
    packet.accept() #accept the packet - redirect the packet back to the NIC stack



nfqueue = NetfilterQueue()
#1 is the iptabels rule queue number, modify is the callback function
nfqueue.bind(1, modify) 
try:
    print("[*] waiting for data")
    nfqueue.run()
except KeyboardInterrupt:
    pass
