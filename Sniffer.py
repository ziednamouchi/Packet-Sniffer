import socket
import struct
import os
import binascii
import sys


def format_mac (mac_raw) :
  string_bytes = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(mac_raw[0]) , ord(mac_raw[1]) , ord(mac_raw[2]), ord(mac_raw[3]), ord(mac_raw[4]) , ord(mac_raw[5]))
  return string_bytes

def Analyse_Ethernet_Header(data):

    ip_bool = False

    dest_mac, src_mac, eth_proto = struct.unpack('! 6s 6s H', data[:14])

    print("###########################ETHERNET##############################")
    print("\nSOURCE: {}".format(format_mac(dest_mac)))
    print("DESTINATION: {}".format(format_mac(src_mac)))
    print("Ethertype: "+"(hex): {}, (dec): {} ".format(hex(eth_proto) , eth_proto))
    print("\n")

    if eth_proto == 0x0800 :
        ip_bool = True

    data = data[14:]
    return data , ip_bool

def Analyse_Ip_Header(data):

    next_protocol = ""

    ip_header = struct.unpack('! 6H 4s 4s' , data[:20])
    ip_boolVersion = ip_header[0] >> 12
    ip_IHL = (ip_header[0] >> 8) & 0x0f
    ip_ToS = ip_header[0] & 0x00ff
    ip_Total_Length = ip_header[1]
    ip_Identification = ip_header[2]
    ip_Flags = ip_header[3] >> 13
    ip_Fragment_Offset = ip_header[3] & 0x1fff
    ip_TTL = ip_header[4] >> 8
    ip_next_Protocol = ip_header[4] & 0x00ff
    ip_Header_Checksum = ip_header[5]
    ip_Source_Address = socket.inet_ntoa(ip_header[6])
    ip_Destination_Address = socket.inet_ntoa(ip_header[7])

    print("\n#############################IP################################")
    print("\n\tVersion : {} ".format(ip_boolVersion))
    print("\tIHL : {} ".format(ip_IHL))
    print("\tToS : {} ".format(ip_ToS))
    print("\tTotal Length : {} ".format(ip_Total_Length))
    print("\tIdentification : {} ".format(ip_Identification))
    print("\tFlags : {} ".format(ip_Flags))
    print("\tFragment_Offset : {} ".format(ip_Fragment_Offset))
    print("\tTTL : {} ".format(ip_TTL))
    print("\tProtocol : {} ".format(ip_next_Protocol))
    print("\tHeader Checksum : {} ".format(ip_Header_Checksum))
    print("\tSource Address : {}, Destination Address : {}".format(ip_Source_Address,ip_Destination_Address))
    print("\n")


    if ip_next_Protocol == 6:
        next_protocol = "TCP"
    if ip_next_Protocol == 17:
        next_protocol = "UDP"
    if ip_next_Protocol == 1:
         next_protocol = "ICMP"

    data = data[20:]
    return data , next_protocol

def Analyse_TCP_Header(data):
    tcp_header = struct.unpack('! 2H 2I 4H' , data[:20])
    tcp_src_port = tcp_header[0]
    tcp_dest_port = tcp_header[1]
    tcp_seq_num = tcp_header[2]
    tcp_ack_num = tcp_header[3]
    tcp_data_offset = tcp_header[4] >> 12
    tcp_reserved = (tcp_header[4] >> 6) & 0x03ff
    tcp_flags = tcp_header[4] & 0x003f
    flag_urg = tcp_flags & 0x0020
    flag_ack = tcp_flags & 0x0010
    flag_psh = tcp_flags & 0x0008
    flag_rst = tcp_flags & 0x0004
    flag_syn = tcp_flags & 0x0002
    flag_fin = tcp_flags & 0x0001
    tcp_window = tcp_header[5]
    tcp_checksum = tcp_header[6]
    tcp_urgent_pointer = tcp_header[7]

    print("\n#############################TCP################################")
    print("\tSource Port : {} ".format(tcp_src_port))
    print("\tDestination Port : {} ".format(tcp_dest_port))
    print("\tSequence Number : {} ".format(tcp_seq_num))
    print("\tacknowledgement Number : {} ".format(tcp_ack_num))
    print("\tData Offset : {} ".format(tcp_data_offset))
    print("\tReserved : {} ".format(tcp_reserved))
    print("\tFlags : {} ".format(tcp_flags))
    print("\t\turg : {} ".format(flag_urg))
    print("\t\tack : {} ".format(flag_ack))
    print("\t\tpsh : {} ".format(flag_psh))
    print("\t\trst : {}".format(flag_rst))
    print("\t\tsyn : {} ".format(flag_syn))
    print("\t\tfin : {} ".format(flag_fin))
    print("\tWindow : {}".format(tcp_window))
    print("\tCecksum : {} ".format(tcp_checksum))
    print("\tUrgent Pointer : {} ".format(tcp_urgent_pointer))
    print("\n")

    data = data[20:]
    return data

def Analyse_UDP_Header(data):
    udp_header = struct.unpack("! 4H", data[:8])
    udp_src_port = udp_header[0]
    udp_dest_port = udp_header[1]
    udp_length = udp_header[2]
    udp_checksum = udp_header[3]

    print("\n#############################UDP################################")
    print("\n\tSource Port : {} ".format(udp_src_port))
    print("\tDestination Port : {} ".format(udp_dest_port))
    print("\tLength : {} ".format(udp_length))
    print("\tChecksum : {} ".format(udp_checksum))


    data = data[8:]
    return data

def Analyse_ICMP_header(data):
    icmp_header = struct.unpack('!BBH' , data[:4])
    icmp_type = icmp_header[0] >> 8
    icmp_code = icmp_header[1] & 0x00ff
    icmp_checksum = icmp_header[2]

    print("\n#############################ICMP################################")
    print("\n\tType : {} ".format(icmp_type))
    print("\tCode : {} ".format(icmp_code))
    print("\tChecksum : {} ".format(icmp_checksum))

    data = data[:8]
    return data


def main():
    try:
        sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    except socket.error , msg:
        print 'Socket could not be created. Error Code : ' + str(message[0]) + ' Message ' + message[1]
        sys.exit()

    ethernet_frame, addr = sock.recvfrom(65536)
    data ,ip_bool = Analyse_Ethernet_Header(ethernet_frame)

    if ip_bool:
        data , next_protocol = Analyse_Ip_Header(data)
    else:
        return


    if next_protocol == "TCP":
        data = Analyse_TCP_Header(data)
    elif next_protocol == "UDP":
        data = Analyse_UDP_Header(data)
    elif next_protocol == "ICMP":
        data = Analyse_ICMP_header(data)
    else:
        return

while True:
    main()
