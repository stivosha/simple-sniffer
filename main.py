import socket
from printer import get_all_frames_str
from arg_parser import parse_args
from pcap.pcap_file import PcapFile


class Sniffer:
    def __init__(self, args):
        self.conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        self.args = args

    def start(self):
        if self.args.pcap is not None:
            self.pcap_mod()
        else:
            if self.args.count is not None:
                for i in range(self.args.count):
                    raw_data, addr = self.conn.recvfrom(65536)
                    print(get_all_frames_str(raw_data))
            else:
                while True:
                    raw_data, addr = self.conn.recvfrom(65536)
                    print(get_all_frames_str(raw_data))

    def pcap_mod(self):
        data = {i: self.conn.recvfrom(65536)[0] for i in range(self.args.count)}
        PcapFile(self.args.pcap).write_pcap(data)


if __name__ == '__main__':
    sniffer = Sniffer(parse_args())
    sniffer.start()
