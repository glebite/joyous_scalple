"""
joyous.py - pcap to python bytes output

python joyous.py -i input.pcap -o output.py

Output should be something along the lines of:

# IP src   192.168.1.5
# IP sport 5000
# IP dst   192.168.2.239
# IP dport 6000
data = bytes([0xa9, 0x03, 0x00 ...])
"""
import scapy
import sys


class Joyous(object):
    def __init__(self):
        pass


def main(arguments):
    pass


if __name__ == "__main__":
    main(sys.argv)
