import binascii
#import module
import socket
import struct



def inspect_ip_packet(packet: memoryview) -> None:
    iph = struct.unpack('!BBHHHBBH4s4s' , packet[0:20])

    version_ihl = iph[0]
    version, ihl = version_ihl >> 4, version_ihl & 0xF
    iph_length = ihl * 4
    ttl, protocol = iph[5], iph[6]
    s_addr, d_addr = socket.inet_ntoa(iph[8]), socket.inet_ntoa(iph[9])

    tcp_header = packet[iph_length:iph_length + 20]
    tcph = struct.unpack('!HHLLBBHHH' , tcp_header)

    source_port, dest_port = tcph[0], tcph[1]
    sequence, acknowledgement = tcph[2], tcph[3]
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4


    h_size = iph_length + tcph_length * 4
    data_size = len(packet) - h_size

    #get data from the packet
    data = packet[h_size:]

    #print(f'{len(packet)}  {packet.__len__()}')

    if 8080 == source_port or 8080 == dest_port:
        print(f'{s_addr}:{source_port} ->  {d_addr}:{dest_port}  ttl: {ttl}')
        print(data.tobytes())


def sniff_ip_traffic() -> None:
    #create an INET, raw socket
    sock: socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    # receive a packet
    while True:
        recv = sock.recvfrom(65565)
        packet = memoryview(recv[0])
        inspect_ip_packet(packet)




def inspect_ethernet_packet(packet: memoryview) -> None:
    # parse ethernet header
    eth_length: int = 14

    eth_header = packet[:eth_length]
    eth = struct.unpack('!6s6sH', eth_header)
    eth_protocol = socket.ntohs(eth[2])
    stc_mac, dst_mac = eth_header[0:6], packet[6:12]

    print(len(packet))


    # Parse IP packets, IP Protocol number = 8
    if eth_protocol == 8:
        # Parse IP header take first 20 characters for the ip header

        iph = struct.unpack('!BBHHHBBH4s4s' , packet[eth_length : 20 + eth_length])

        version_ihl = iph[0]
        version, ihl = version_ihl >> 4, version_ihl & 0xF
        iph_length = ihl * 4
        ttl, protocol = iph[5], iph[6]
        s_addr, d_addr = socket.inet_ntoa(iph[8]), socket.inet_ntoa(iph[9])

        #TCP protocol
        if protocol == 6 :
            t = iph_length + eth_length
            tcp_header = packet[t : t + 20]
            tcph = struct.unpack('!HHLLBBHHH' , tcp_header)

            source_port, dest_port = tcph[0], tcph[1]
            sequence, acknowledgement = tcph[2], tcph[3]
            doff_reserved = tcph[4]
            tcph_length = doff_reserved >> 4

            h_size = iph_length + tcph_length * 4 + 14
            data_size = len(packet) - h_size # TODO:

            #get data from the packet
            data = packet[h_size:]

            # print(f'{len(packet)}  {packet.__len__()}')
            if 8080 == source_port or 8080 == dest_port:
                # print(f'{s_addr}:{source_port} ->  {d_addr}:{dest_port}  ttl: {ttl}')
                # print(data.tobytes())

                print(14)
                print(iph_length)
                print(tcph_length * 4 )
                print()


        '''
        #ICMP Packets
        elif protocol == 1 :
            u = iph_length + eth_length
            icmph_length = 4
            icmp_header = packet[u:u+4]

            #now unpack them :)
            icmph = unpack('!BBH' , icmp_header)

            icmp_type = icmph[0]
            code = icmph[1]
            checksum = icmph[2]

            print 'Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum)

            h_size = eth_length + iph_length + icmph_length
            data_size = len(packet) - h_size

            #get data from the packet
            data = packet[h_size:]

            print 'Data : ' + data

            #UDP packets
        elif protocol == 17 :
            u = iph_length + eth_length
            udph_length = 8
            udp_header = packet[u:u+8]

            #now unpack them :)
            udph = unpack('!HHHH' , udp_header)

            source_port = udph[0]
            dest_port = udph[1]
            length = udph[2]
            checksum = udph[3]

            print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum)

            h_size = eth_length + iph_length + udph_length
            data_size = len(packet) - h_size

            #get data from the packet
            data = packet[h_size:]

            print 'Data : ' + data
        '''


def sniff_ethernet_traffic() -> None:
    #create an INET, raw socket
    sock: socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

    # receive a packet
    while True:
        recv = sock.recvfrom(65565)
        packet = memoryview(recv[0])
        inspect_ethernet_packet(packet)



if __name__ == '__main__':
    # sniff_ip_traffic()
    sniff_ethernet_traffic()