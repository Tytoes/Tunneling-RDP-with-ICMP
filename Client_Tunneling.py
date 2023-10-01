from scapy.all import *
import pydivert

def handle_outgoing_packet(packet):
    if packet.ip and packet.ip.protocol == pydivert.Protocol.TCP and packet.tcp.dst_port == 3389:
        # Transfering the packet info to a Scapy packet
        # The packet comes in Pydivert format, so need to get out the important info one by one

        #eth_dst = packet.eth. - Not needed...
        rdp_src = packet.ip.src_addr
        rdp_dst = packet.ip.dst_addr
        src_port = packet.tcp.src_port
        dst_port = packet.tcp.dst_port
        rdp_ttl = packet.ip.ttl
        seq_num = packet.tcp.seq_num
        ack_num = packet.tcp.ack_num
        window = packet.tcp.window_size
        tcp_payload = packet.tcp.payload
        tcp_flags = ''
        if (packet.tcp.urg == True):
            tcp_flags+='U'
        if (packet.tcp.syn == True):
            tcp_flags+='S'
        if (packet.tcp.ack == True):
            tcp_flags+='A'
        if (packet.tcp.psh == True):
            tcp_flags+='P'
        if (packet.tcp.rst == True):
            tcp_flags+='R'
        if (packet.tcp.fin == True):
            tcp_flags+='F'
        rdp_packet = IP(src=rdp_src,dst=rdp_dst,flags=2,ttl=rdp_ttl)/TCP(sport=src_port,dport=dst_port,\
                                seq=seq_num,ack=ack_num,window=window,flags=tcp_flags)/Raw(load=bytes(tcp_payload))

        # Create an ICMP packet
        print(packet.ip.dst_addr)
        icmp_dest_ip = str(packet.ip.dst_addr)

        icmp_packet = IP(dst=icmp_dest_ip, ttl=128)/ICMP(type=8, code=0)/Raw(load=rdp_packet)
        
        # Set the payload of the ICMP packet as the captured RDP packet
        

        # Print original and modified packets, again only for Debugging reasong - can be deleted.
        print("Original Packet:")
        print(packet)
        print("ICMP Packet:")
        print(icmp_packet.show())
        print()
        print("RDP Packet:")
        print(rdp_packet.show())
        print()
        
        return icmp_packet

    return 

# These 2 function (modify and scapy_sniffing) are not being used!,they were supppose to in the beggining
# So I left them here but it also can be deleted.

def modify(scapy_packet):
    print('Got to trying')
    icmp_dest_ip = scapy_packet[IP].dst
    icmp_packet = IP(dst=icmp_dest_ip, ttl=128)/ICMP(type=8, code=0)/Raw(load=scapy_packet)
    print(scapy_packet.show())
    send(icmp_packet)
    return

def scapy_sniff():
    print('Got to scapy_sniff')
    packets = sniff(iface='VMware Network Adapter VMnet8',filter="port 3389", prn=trying)
    print(packet.show())
    
# Create a WinDivert instance and set the filter
def pydiv():
    # Sniffing RDP using pydivert
    w = pydivert.WinDivert("tcp.DstPort == 3389")
    w.open()

    # Start capturing and modifying packets
    for py_packet in w:
        
       # Sending the Packet into handle_outgoing_packet function and saving the return (ICMP packet)
       # In new_packet variable
       new_packet = handle_outgoing_packet(py_packet)
       
       # Send the ICMP packet
       send(new_packet)

if __name__ == "__main__":
    pydiv()

