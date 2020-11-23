import socket
from printer import get_all_frames_str


def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = conn.recvfrom(65536)
        print(get_all_frames_str(raw_data))


if __name__ == '__main__':
    main()
