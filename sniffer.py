import socket
import struct
import textwrap

# Creating a raw socket to capture the packets from the data link layer
raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    
def main():
    while True:
        # Receives data until Ctrl+C is pressed
        try:
            raw_data, address = raw_socket.recvfrom(65535) 
        
        except KeyboardInterrupt:
            raw_socket.close()
            break

        eth_type, eth_data = eth_unpack(raw_data)
        
        # Checking Ethernet type
        match eth_type:
            case 0x0800:
                protocol, ip_data = ipv4_unpack(eth_data)

            case 0x86DD:
                protocol, ip_data = ipv6_unpack(eth_data)
        
            case 0x0806:
                protocol = None
                print("\nARP protocol.")

            case _:
                protocol = None
                print("\nUncommon EtherType protocol.")


        # Checking protocol / next header
        match protocol:
            case 1 | 58:
                icmp_unpack(ip_data)

            case 6:
                tcp_unpack(ip_data)

            case 17:
                udp_unpack(ip_data)
            
            case None:
                print("\nNo IP protocol field value.")

            case _:
                print("\nUncommon protocol.")
        
        print("\n------------------------------------------------------------\n")


# Unpacking

def eth_unpack(data):
    eth_header = data[:14]
    eth_data = data[14:]

    # Unpacking the ethernet header
    mac_dest, mac_src, eth_type = struct.unpack("!6s6sH", eth_header)
    print("Ethernet Header:")
    print(f" - Destination MAC address: {':'.join('%02x' % b for b in mac_dest)}")
    print(f" - Source MAC address: {':'.join('%02x' % b for b in mac_src)}")
    print(f" - Ethernet protocol: {hex(eth_type)}")

    return eth_type, data[14:]

def ipv4_unpack(data):
    ipv4_header = data[:20]
    version, tos, length, identification, flags, ttl, protocol, checksum, src_addr, dest_addr = struct.unpack("!BBHHHBBH4s4s", ipv4_header)
    
    src_addr = socket.inet_ntop(socket.AF_INET, src_addr)
    dest_addr = socket.inet_ntop(socket.AF_INET, dest_addr)
    
    print("\nIPV4 Header:")
    print(f" - Source address: {src_addr}")
    print(f" - Destination address: {dest_addr}")
    print(f" - Protocol: {protocol}")

    return protocol, data[20:]


def ipv6_unpack(data):
    ipv6_header = data[:40]
    vers_traffic, flow_label, payload_length, next_header, hop_limit, src_addr, dest_addr = struct.unpack("!HHHBB16s16s", ipv6_header)
    
    src_addr = socket.inet_ntop(socket.AF_INET6, src_addr)
    dest_addr = socket.inet_ntop(socket.AF_INET6, dest_addr)
 
    print("\nIPV6 Header:")
    print(f" - Source address: {src_addr}")
    print(f" - Destination address: {dest_addr}")
    print(f" - Protocol: {next_header}")

    return next_header, data[40:]


def icmp_unpack(data):
    icmp_header = data[:4]
    icmp_type, icmp_code, checksum = struct.unpack("!BBH", icmp_header)
    
    print("\nICMP Header:")
    print(f" - Type: {icmp_type}")
    print(f" - Code: {icmp_code}")
    print(f" - Checksum: {checksum}")

    print("\nData:") 
    print(format_data("\t", data[4:]))


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

    print("\nTCP Header:")
    print(f" - Source Port: {src_port}")
    print(f" - Destination Port: {dest_port}")
    print(f" - Sequence Number: {sqnc}")
    print(f" - Acknowledgement Number: {ack}")
    print(f" - Data Offset: {offset}")
    print(f" - URG: {urg_flag}, ACK: {ack_flag}, PSH: {psh_flag}.")
    print(f" - RST: {rst_flag}, SYN: {syn_flag}, FIN: {fin_flag}.")
   
    print("\nData:") 
    print(format_data("\t", data[14:]))


def udp_unpack(data):
    udp_header = data[:8]
    src_port, dest_port, length, checksum = struct.unpack("!HHHH", udp_header)
    
    print("\nUDP Header:")
    print(f" - Source Port: {src_port}")
    print(f" - Destination Port: {dest_port}")
    
    print("\nData:") 
    print(format_data("\t", data[8:]))


# Formatting data from upper OSI layers

def format_data(tab, data, length = 80):
    length -= len(tab)
    data = ''.join(r'\x{:02}'.format(byte) for byte in data)
    return '\n'.join([tab + line for line in textwrap.wrap(data, length)])


if __name__ == "__main__":
    main()
