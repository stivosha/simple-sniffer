import struct
import socket


def get_mac_addr(bytes_addr):
    bytes_str = map("{:02x}".format, bytes_addr)
    return ":".join(bytes_str).upper()


def get_ipv4_addr(addr):
    return ".".join(map(str, addr))


def parse_tcp_flags(offset_reserved_flags):
    urg = (offset_reserved_flags & 32) >> 5
    ack = (offset_reserved_flags & 16) >> 4
    psh = (offset_reserved_flags & 8) >> 3
    rst = (offset_reserved_flags & 4) >> 2
    syn = (offset_reserved_flags & 2) >> 1
    fin = offset_reserved_flags & 1
    return [urg, ack, psh, rst, syn, fin]


def parse_ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack("! 6s 6s H", data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


def parse_ipv4_header(data):
    (version_and_header_len, tos, total_len,
     identification, flags_and_offset,
     ttl, proto, checksum,
     s_ip, d_ip) = struct.unpack('! B B H H H B B H 4s 4s', data[0:20])
    s_ip = get_ipv4_addr(s_ip)
    d_ip = get_ipv4_addr(d_ip)
    version = version_and_header_len >> 4
    header_len = (version_and_header_len & 15) * 4
    flags = flags_and_offset >> 13
    fragment_offset = flags_and_offset & 8191
    return (version, header_len, tos, total_len,
            identification, flags, fragment_offset,
            ttl, proto, checksum,
            s_ip, d_ip, data[header_len:])


def parse_ipv6_header(data):
    version = data[0] >> 4
    # version_traffic_class_flow_label = struct.unpack('!H B B', data[0:4])
    payload, proto, limit, s_addr, d_addr = struct.unpack('!H B B 16s 16s', data[4:40])
    s_addr = get_mac_addr(s_addr)
    d_addr = get_mac_addr(d_addr)
    return (version,
            payload, proto, limit,
            s_addr, d_addr)


def parse_tcp_header(data):
    (src_port, dest_port,
     sequence,
     acknowledgement,
     offset_flags, wind_size,
     checksum, urgent_pointer) = struct.unpack('! H H L L H H H H', data[:20])
    src_port = str(src_port)
    dest_port = str(dest_port)
    offset = (offset_flags >> 12) * 4
    return (src_port, dest_port,
            sequence,
            acknowledgement,
            offset, parse_tcp_flags(offset_flags), wind_size,
            checksum, urgent_pointer,
            data[offset:])


def parse_udp_header(data):
    src_port, dest_port, data_len, checksum = struct.unpack('! H H H H', data[:8])
    return src_port, dest_port, data_len, checksum, data[8:]
