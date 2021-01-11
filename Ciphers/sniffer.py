"""	Port 0 is reserved by IANA, it is technically invalid to use, but possible.
It is sometimes used to fingerprint machines, because different operating systems respond to this port in different ways.
Some ISPs may block it because of exploits. Port 0 can be used by applications when calling the bind() command
to request the next available dynamically allocated source port number. 
"""

import socket
import struct
import textwrap

TAB_1 = '\t   '
TAB_2 = '\t\t   '
TAB_3 = '\t\t\t   '
TAB_4 = '\t\t\t\t   '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '




# Return properly formated MAX address
# (ie AA:BB:CC:EE:FF)
def get_mac_addr(bytes_addr):
    bytes_addr = map('{:02x}'.format, bytes_addr) # Striping out everything and making sure that there are only 2 decimal places for each one
    return ':'.join(bytes_addr).upper()

# Ethernet frame
def ethernet_frame(data): #unpacking those ones and zeros
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])                        # Converting data to and from bytes, '!'--> treating this as network data bit/little endians
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]    # H is protocol
                  
# Unapcks IPv4 packet
def ipv4_packet(data):
    version_header_length = data[0] # version [0-3] - IHL (Header Length) [4-7]     ### Data[0] gives me the first byte --> 8 bits
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4            ### 15 in binary: 1111, Puta 4 ili shift za 4  isto mu se vata..
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])  # 8X znaci da se preskace 8 puta a B iza toga je Byte, znaci 8 bajta se preskace
    return  version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

# Returns properly formatted IPv4 address
# Like: 127.0.0.1
def ipv4(addr):
    return '.'.join(map(str, addr))

#Unpacks ICMP packet
def icmp_packet(data):
    icmp_type, code, schecksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, schecksum, data[4:] # data[4:]->payload

#Unpacks TCP packet
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]
    

def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    
    string2 = bytes.fromhex(string).decode('iso-8859-1')

    return '\n'.join([prefix + line for line in textwrap.wrap(string2, size)])

def write_packet_to_file(file_name, mode, text, ip_addr):
    varToAppend = f'{ip_addr}: {text}\n'

    appendFile = open(f'{file_name}.txt', f'{mode}')

    appendFile.write(varToAppend)
    appendFile.close()




if __name__ == "__main__":
    # host = socket.gethostname()
    # conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    # # create a raw socket and bind it to the public interface
    # conn.bind((host, 0))
    # conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    # #receives all packets
    # conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    source_addr = str(input("Enter source address: "))
    destination_addr = str(input("Enter destination address: "))

    
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    
    
    while True:
        raw_data, addr = conn.recvfrom(65536)  # Data that comes across the network, bunch of 0 and 1
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)   # Extracting the ethernet frame
        # print("\nEthernet Frame:")
        # print(TAB_1 + "Destination: {}, Source: {}, Protocol: {}".format(dest_mac, src_mac, eth_proto))

        # 8 for IPv4
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)

            if(str(src) == source_addr and str(target) == destination_addr) or (str(target) == source_addr and str(src) == destination_addr):
                # print(TAB_1 + 'IPv4 Packet: ')
                # print(TAB_2 + 'Version: {}, Header Length:  {}, TTL: {}'.format(version, header_length, ttl))
                # print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))
                
                # ICMP
                # if proto == 1:
                #     icmp_type, code, schecksum, data = icmp_packet(data)
                #     print(TAB_1 + 'ICMP Packet: ')
                #     print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, schecksum))
                #     print(TAB_2 + 'Data: ')
                #     print(format_multi_line(DATA_TAB_3, data))192.168.1.8
                # TCP
                if proto == 6:
                    (src_port, dest_port, sequence, acknowledgment,
                    flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(data)
                    if flag_psh == 1:
                        print(TAB_1 + 'TCP Segment: ')
                        print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                        print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(sequence, acknowledgment))
                        print(TAB_2 + 'Flags: ')
                        print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                        print(format_multi_line(DATA_TAB_3, data))
                        write_packet_to_file("Sniffed_Packages", 'a', format_multi_line(DATA_TAB_3, data), str(src))