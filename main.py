import socket
from printer import get_all_frames_str
from arg_parser import parse_args


class Sniffer:
    def __init__(self, args):
        self.args = args

    def start(self):
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        if self.args.count is not None:
            for i in range(self.args.count):
                raw_data, addr = conn.recvfrom(65536)
                print(get_all_frames_str(raw_data))
        else:
            while True:
                raw_data, addr = conn.recvfrom(65536)
                print(get_all_frames_str(raw_data))


if __name__ == '__main__':
    sniffer = Sniffer(parse_args())
    sniffer.start()
