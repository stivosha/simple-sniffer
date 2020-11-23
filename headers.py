from contextlib import redirect_stdout
from levels import Level
import io
import helpers
import hexdump

TAB_1 = '|\t- '
TAB_2 = '|\t\t- '
TAB_3 = '|\t\t\t- '


class Ethernet:
    def __init__(self, data):
        (self.d_mac, self.s_mac,
         self.next_header, self.next_data) = helpers.parse_ethernet_frame(data)
        self.level = Level.DATA_LINK
        self.packet_name = 'eth'

    def to_str(self):
        s = '| Ethernet:\n'
        s += TAB_1 + f'Destination MAC: {self.s_mac}, Source MAC: {self.d_mac}, Protocol: {self.next_header}.'
        return s


class IPv4:
    def __init__(self, data):
        self.level = Level.NETWORK
        self.packet_name = 'ipv4'
        (self.version, self.header_len, self.TOS, self.total_len,
         self.identification, self.flags, self.fragment_offset,
         self.TTL, self.next_header, self.checksum,
         self.s_ip, self.d_ip,
         self.next_data) = helpers.parse_ipv4_header(data)

    def to_str(self):
        s = '| IPv4:\n' + TAB_1
        s += f'Version: {self.version}, Header Length: {self.header_len}, ' \
             f'ToS/DSCP: {self.TOS}, Total Length: {self.total_len}, ' \
             f'Identificator: {self.identification}.\n' + TAB_1
        s += f'Flags: {self.flags}, Fragmentation Offset: {self.fragment_offset},' \
             f' TTL: {self.TTL}, Protocol: {self.next_header}, ' \
             f'Header Checksum: {self.checksum}.\n' + TAB_1
        s += f'Source IP: {self.s_ip}, Destination IP: {self.d_ip}.\n'
        return s


class IPv6:
    def __init__(self, data):
        self.level = Level.NETWORK
        self.packet_name = 'ipv6'
        (self.version,
         self.payload, self.next_header, self.limit,
         self.s_ip, self.d_ip,
         self.next_data) = helpers.parse_ipv6_header(data)

    def to_str(self):
        s = '| IPv6:\n'
        s += TAB_1 + f'Version: {self.version}, Payload label: {self.payload}.\n'
        s += TAB_1 + f'Protocol: {self.next_header}, HOP Limit: {self.limit}.\n'
        s += TAB_1 + f'Source IP: {self.s_ip}, Destination IP: {self.d_ip}.\n'
        return s


class TCP:
    def __init__(self, data):
        self.level = Level.TRANSPORT
        self.packet_name = 'tcp'
        self.next_header = -2
        (self.src_port, self.dest_port,
         self.sequence,
         self.acknowledgement,
         self.offset, self.flags, self.w_size,
         self.checksum, self.urgent_pointer,
         self.next_data) = helpers.parse_tcp_header(data)

    def to_str(self):
        s = '| TCP Segment:\n'
        s += TAB_1 + f'Source Port: {self.src_port}, Destination Port: {self.dest_port}\n'
        s += TAB_1 + f'Sequence: {self.sequence}, Acknowledgment: {self.acknowledgement}\n'
        s += TAB_1 + f'Window Size: {self.w_size}\n'
        s += TAB_1 + f'Checksum: {self.checksum}, Urgent Point: {self.urgent_pointer}.\n'
        s += TAB_1 + 'Flags:\n'
        s += TAB_2 + f'URG: {self.flags[0]}, ACK: {self.flags[1]}, PSH: {self.flags[2]}\n'
        s += TAB_2 + f'RST: {self.flags[3]}, SYN: {self.flags[4]}, FIN: {self.flags[5]}\n'
        return s


class UDP:
    def __init__(self, data):
        self.level = Level.TRANSPORT
        self.packet_name = 'udp'
        self.next_header = -2
        (self.s_port, self.d_port,
         self.length, self.checksum,
         self.next_data) = helpers.parse_udp_header(data)

    def to_str(self):
        s = '| UDP Segment:\n'
        s += TAB_1 + f'Source Port: {self.s_port}, Destination Port: {self.d_port}.\n'
        s += TAB_1 + f'Length: {self.length}, Checksum: {self.checksum}.\n'
        return s


class BinaryData:
    def __init__(self, data):
        self.data = data
        self.level = Level.BINARY_DATA
        self.packet_name = 'binary_data'

    def to_str(self):
        s = HexDump(self.data).hex_string
        return '| Data:\n' + str(s) + "\n"


class UnknownPacket:
    def __init__(self, data):
        self.level = Level.UNKNOWN
        self.data = data

    def to_str(self, proto):
        s = HexDump(self.data).hex_string
        return f'| Unknown protocol number: {proto}\n' + str(s) + "\n"


class HexDump:
    def __init__(self, binary_data):
        with io.StringIO() as buf, redirect_stdout(buf):
            generator = hexdump.hexdump(binary_data, 'generator')
            for line in generator:
                print('| ' + line)
            self.hex_string = buf.getvalue()
