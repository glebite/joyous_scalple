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
from optparse import OptionParser


class Joyous(object):
    def __init__(self, arguments):
        self.in_file_name = arguments.in_file_name
        self.out_file_name = arguments.out_file_name


def main(arguments):
    parser = OptionParser()
    parser.add_option('-o', '--output', dest='out_file_name',
                      default=False, help='Output file name')
    parser.add_option('-i', '--input', dest='in_file_name',
                      default=False, help='Input file name')
    (options, args) = parser.parse_args(arguments)
    translator = Joyous(options)
    translator.run()


if __name__ == "__main__":
    main(sys.argv)
