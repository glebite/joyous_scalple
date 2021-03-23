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
from scapy.all import *
import sys
from os import path
from optparse import OptionParser


class Joyous(object):
    def __init__(self, arguments):
        self.in_file_name = arguments.in_file_name
        self.out_file_name = arguments.out_file_name

    def run(self):
        if path.exists(self.in_file_name):
            self.capture = rdpcap(self.in_file_name)
        else:
            print('error')


def main(arguments):
    parser = OptionParser()
    parser.add_option('-o', '--output', dest='out_file_name',
                      help='Output file name')
    parser.add_option('-i', '--input', dest='in_file_name',
                      help='Input file name')
    (options, args) = parser.parse_args(arguments)
    print(f'Type: {options}')
    if options.out_file_name is None or options.in_file_name is None:
        print("Um - failure...")
    else:
        translator = Joyous(options)
        translator.run()


if __name__ == "__main__":
    main(sys.argv)
