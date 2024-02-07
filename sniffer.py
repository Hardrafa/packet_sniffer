import socket
import struct

separate = "\n------------------------------------------------------------\n"

# Creating a raw socket to capture the packets from the data link layer
raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    
def main():
    while True:
        # Receiving data from the socket with maximum buffer size
        raw_data, address = raw_socket.recvfrom(65535)
        
        # Separating the ethernet header from the data
        eth_header = raw_data[:14]
        eth_data = raw_data[14:]

        # Unpacking the ethernet header
        mac_dest, mac_src, eth_type = struct.unpack("!6s6sH", eth_header)
        print("Ethernet Header:")
        print(f" - Destination MAC address: {':'.join('%02x' % b for b in mac_dest)}")
        print(f" - Source MAC address: {':'.join('%02x' % b for b in mac_src)}")
        print(f" - Ethernet protocol: {hex(eth_type)}")
        
        # Checking Internet Protocol
        if eth_type == 0x0800:
            src_addr, dest_addr, protocol, ip_data = ipv4_unpack(eth_data)
            print("     IPV4 Header:")
            print(f"      - Source address: {src_addr}")
            print(f"      - Destination address: {dest_addr}")
            print(f"      - Protocol: {protocol}")

        elif eth_type == 0x86DD:
            src_addr, dest_addr, protocol, ip_data = ipv6_unpack(eth_data)
            print("     IPV6 Header:")
            print(f"      - Source address: {src_addr}")
            print(f"      - Destination address: {dest_addr}")
            print(f"      - Protocol: {protocol}")
        
        elif eth_type == 0x0806:
            print("     ARP protocol.")

        else:
            print("Uncommon EtherType protocol.")

        # Checking payload
        if protocol == 6:
            src_port, dest_port, sqnc, ack, offset, urg_flag, ack_flag, psh_flag, rst_flag, syn_flag, fin_flag, tcp_data = tcp_unpack(ip_data)
            print("         TCP Header:")
            print(f"          - Source Port: {src_port}")
            print(f"          - Destination Port: {dest_port}")
            print(f"          - Sequence Number: {sqnc}")
            print(f"          - Acknowledgement Number: {ack}")
            print(f"          - Data Offset: {offset}")
            print(f"          - URG: {urg_flag}, ACK: {ack_flag}, PSH: {psh_flag}, RST: {rst_flag}, SYN: {syn_flag}, FIN {fin_flag}.")

        elif protocol == 17:
            src_port, dest_port, udp_data = udp_unpack(ip_data)
            print("         UDP Header:")
            print(f"          - Source Port: {src_port}")
            print(f"          - Destination Port: {dest_port}")
            
        else:
            print("Uncommon 4th layer protocol or no protocol")
        
        print(separate)

# Unpack IPV4 packet
def ipv4_unpack(data):
    ipv4_header = data[:20]
    version, tos, length, identification, flags, ttl, protocol, checksum, src_addr, dest_addr = struct.unpack("!BBHHHBBH4s4s", ipv4_header)
    
    src_addr = socket.inet_ntop(socket.AF_INET, src_addr)
    dest_addr = socket.inet_ntop(socket.AF_INET, dest_addr)
    
    return src_addr, dest_addr, protocol, data[20:]

# Unpack IPV6 packet
def ipv6_unpack(data):
    ipv6_header = data[:40]
    vers_traffic, flow_label, payload_length, next_header, hop_limit, src_addr, dest_addr = struct.unpack("!HHHBB16s16s", ipv6_header)
    
    src_addr = socket.inet_ntop(socket.AF_INET6, src_addr)
    dest_addr = socket.inet_ntop(socket.AF_INET6, dest_addr)
 
    return src_addr, dest_addr, next_header, data[40:]

# Unpack TCP segment
def tcp_unpack(data):
    tcp_header = data[:14]
    src_port, dest_port, sqnc, ack, offset_reserved_flags = struct.unpack("!HHIIH", tcp_header)
    offset = (offset_reserved_flags >> 12) * 4
    urg_flag = (offset_reserved_flags & 0x0020) >> 5
    ack_flag = (offset_reserved_flags & 0x0010) >> 4
    psh_flag = (offset_reserved_flags & 0x0008) >> 3
    rst_flag = (offset_reserved_flags & 0x0004) >> 2
    syn_flag = (offset_reserved_flags & 0x0002) >> 1
    fin_flag = (offset_reserved_flags & 0x0001)

    return src_port, dest_port, sqnc, ack, offset, urg_flag, ack_flag, psh_flag, rst_flag, syn_flag, fin_flag, data[14:]

def udp_unpack(data):
    udp_header = data[:8]
    src_port, dest_port, length, checksum = struct.unpack("!HHHH", udp_header)
    
    return src_port, dest_port, data[8:]



if __name__ == "__main__":
    main()
