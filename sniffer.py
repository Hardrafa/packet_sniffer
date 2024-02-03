import socket
import struct

def main():
    # First we'll have to create a socket to capture the packets
    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    
    while True:


if __name__ == "__main__":
    main()
