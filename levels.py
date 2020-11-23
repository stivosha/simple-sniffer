from enum import Enum


class Level(Enum):
    DATA_LINK = 0
    NETWORK = 1
    TRANSPORT = 2
    BINARY_DATA = 3
    UNKNOWN = -1
