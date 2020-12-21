import argparse


def parse_args():
    parser = argparse.ArgumentParser(description="simple sniffer")
    parser.add_argument("-i", "--info", nargs='+', dest='filter', type=str)
    parser.add_argument("-f", "--file", dest='filename', type=str)
    parser.add_argument("-c", "--count", dest='count', type=int)
    return parser.parse_args()
