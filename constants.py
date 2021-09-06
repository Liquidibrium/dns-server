import sys
import random
MSG_SIZE = 512
MSG_MAX_SIZE = 4096
ZONE_FILE_EXT = '.conf'


def write_in_file(*text):
    with open('log_file1.txt', 'a') as f:
        print(*text, '\n', file=f)


def random_id():
    import random
    #  16 size of id
    return random.getrandbits(16)


class ResponseCode():
    NO_ERROR = 0
    FORMAT_ERROR = 1
    SERVER_FAILURE = 2
    NAME_ERROR = 3
    NOT_IMPLEMENTED = 4
    REFUSED = 5


class Types():
    A = 0x1
    NS = 0x2
    CNAME = 0x5
    SOA = 0x6
    MX = 0xF
    TXT = 0X10
    AAAA = 0X1C
    reversed_types = {
        0x1: "A",
        0x2: "NS",
        0x5: "CNAME",
        0x6: "SOA",
        0xF: "MX",
        0x10: "TXT",
        0X1C: "AAAA"
    }


"""
root DNS server addresses:
A.ROOT-SERVERS.NET.		3600000      A     198.41.0.4
B.ROOT-SERVERS.NET.		3600000      A     192.228.79.201
C.ROOT-SERVERS.NET.		3600000      A     192.33.4.12
D.ROOT-SERVERS.NET.		3600000      A     199.7.91.13
E.ROOT-SERVERS.NET.		3600000      A     192.203.230.10
F.ROOT-SERVERS.NET.		3600000      A     192.5.5.241
G.ROOT-SERVERS.NET.		3600000      A     192.112.36.4
H.ROOT-SERVERS.NET.		3600000      A     128.63.2.53
I.ROOT-SERVERS.NET.		3600000      A     192.36.148.17
J.ROOT-SERVERS.NET.		3600000      A     192.58.128.30
K.ROOT-SERVERS.NET.		3600000      A     193.0.14.129
L.ROOT-SERVERS.NET.		3600000      A     199.7.83.42
M.ROOT-SERVERS.NET.		3600000      A     202.12.27.33
"""

ROOT_SERVER_IPS = [
    '192.228.79.201',
    '192.58.128.30',
    '192.33.4.12',
    '199.7.91.13',
    '192.203.230.10',
    '192.5.5.241',
    '192.112.36.4',
    '128.63.2.53',
    '192.36.148.17',
    '193.0.14.129',
    '199.7.83.42',
    '202.12.27.33',
    '198.41.0.4'
]
