from headers import Ethernet, UnknownPacket, BinaryData
from protocols import parse_protocol


def get_all_frames_str(data):
    frame = Ethernet(data)
    output = frame.to_str()
    data = frame.next_data
    while True:
        frame_constructor = parse_protocol(frame.next_header)
        proto = frame.next_header
        frame = frame_constructor(data)
        if frame_constructor == UnknownPacket:
            output += frame.to_str(proto)
            return output
        output += frame.to_str()
        if frame_constructor == BinaryData:
            return output
        data = frame.next_data
