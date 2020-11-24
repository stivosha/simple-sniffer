import argparse


def parse_args():
    parser = argparse.ArgumentParser(description="simple sniffer")
    parser.add_argument("-i", "--info", nargs='+', dest='filter', type=str)
    parser.add_argument("-f", "--file", dest='filename', type=str)
    return parser.parse_args()
