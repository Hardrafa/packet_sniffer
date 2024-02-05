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
            print(separate)

        elif eth_type == 0x86DD:
            src_addr, dest_addr, protocol, ip_data = ipv6_unpack(eth_data)
            print("     IPV6 Header:")
            print(f"      - Source address: {src_addr}")
            print(f"      - Destination address: {dest_addr}")
            print(f"      - Protocol: {protocol}")
            print(separate)
        
        else:
            print("No Internet Protocol.")
            print(separate)

        # Checking payload
        #if protocol == 

        

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

if __name__ == "__main__":
    main()
