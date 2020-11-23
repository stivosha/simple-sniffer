from enum import Enum
from headers import Ethernet, IPv6, IPv4, UDP, TCP, BinaryData, UnknownPacket


class Protocols(Enum):
    IPV6 = 56710
    IPV4 = 8
    TCP = 6
    UDP = 17
    UNKNOWN_PROTOCOL = -1
    BINARY_DATA_NEXT = -2


protocols = {
    56710: Protocols.IPV6,
    8: Protocols.IPV4,
    6: Protocols.TCP,
    17: Protocols.UDP,
    -2: Protocols.BINARY_DATA_NEXT
}

protocols_to_frame = {
    Protocols.IPV6: IPv6,
    Protocols.IPV4: IPv4,
    Protocols.TCP: TCP,
    Protocols.UDP: UDP,
    Protocols.BINARY_DATA_NEXT: BinaryData,
    Protocols.UNKNOWN_PROTOCOL: UnknownPacket
}


def parse_protocol(number):
    if number in protocols:
        return protocols_to_frame[protocols[number]]
    return protocols_to_frame[Protocols.UNKNOWN_PROTOCOL]
