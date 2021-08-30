#!/usr/bin/env python
#
# from:
# https://gist.github.com/yunazuno/d7cd7e1e127a39192834c75d85d45df9
import socket
import fcntl
import struct
import array

SIOCETHTOOL = 0x8946
ETHTOOL_GSTRINGS = 0x0000001b
ETHTOOL_GSSET_INFO = 0x00000037
ETHTOOL_GSTATS = 0x0000001d
ETH_SS_STATS = 0x1
ETH_GSTRING_LEN = 32


class Ethtool(object):
    def __init__(self, ifname):
        self.ifname = ifname
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)

    def _send_ioctl(self, data):
        ifr = struct.pack('16sP', self.ifname.encode("utf-8"), data.buffer_info()[0])
        return fcntl.ioctl(self._sock.fileno(), SIOCETHTOOL, ifr)

    def get_gstringset(self, set_id):
        sset_info = array.array('B', struct.pack("IIQI", ETHTOOL_GSSET_INFO, 0, 1 << set_id, 0))
        self._send_ioctl(sset_info)
        sset_mask, sset_len = struct.unpack("8xQI", sset_info)
        if sset_mask == 0:
            sset_len = 0

        strings = array.array("B", struct.pack("III", ETHTOOL_GSTRINGS, ETH_SS_STATS, sset_len))
        strings.extend(b'\x00' * sset_len * ETH_GSTRING_LEN)
        self._send_ioctl(strings)
        for i in range(sset_len):
            offset = 12 + ETH_GSTRING_LEN * i
            s = strings[offset:offset+ETH_GSTRING_LEN].tobytes().partition(b'\x00')[0].decode("utf-8")
            yield s

    def get_nic_stats(self):
        strings = list(self.get_gstringset(ETH_SS_STATS))
        n_stats = len(strings)

        stats = array.array("B", struct.pack("II", ETHTOOL_GSTATS, n_stats))
        stats.extend(struct.pack('Q', 0) * n_stats)
        self._send_ioctl(stats)
        for i in range(n_stats):
            offset = 8 + 8 * i
            value = struct.unpack('Q', stats[offset:offset+8])[0]
            yield (strings[i], value)


if __name__ == '__main__':
    import sys
    
    ifname = sys.argv[1]
    et = Ethtool(ifname)
    for k, v in et.get_nic_stats():
        print(f"{k}: {v}")
