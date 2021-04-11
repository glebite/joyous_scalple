#!/usr/bin/env python
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
from scapy.all import rdpcap
from scapy.layers.inet import IP

import sys
from os import path
from optparse import OptionParser


class Joyous(object):
    """Joyous
    """
    def __init__(self, arguments):
        """__init__ - init the class

        :param:  arguments - passed in from main and arg parsing
        :return: None
        """
        self.in_file_name = arguments.in_file_name
        self.out_file_name = arguments.out_file_name
        self.capture = None

    def run(self):
        """run - execute the overall flow of the code

        :param:  None
        :return: None
        """
        if path.exists(self.in_file_name):
            self.capture = rdpcap(self.in_file_name)
        else:
            print(f'# Failure - {self.in_file_name} does not exist.')
            sys.exit(0)
        for packet in self.capture:
            try:
                info = self.dump_to_python(packet[IP].payload)
                if info:
                    print(f'# IP: {packet[IP].src}:{packet[IP].sport} '
                          f'# -> {packet[IP].dst}:{packet[IP].dport}')
                    print(info)
            except IndexError as e:
                print(f'# Packet not supporting IP Layer: {e}.')
                continue

    def dump_to_python(self, data):
        """dump_to_python - dump packet to python list

        :param:  data - the packet data (bytes)
        :return: out_string - the string output of python list
        """
        if len(data) <= 32:
            return None
        data = bytes(data)
        out_string = "data = ["
        counter = 0
        for byte in data[32:]:
            if counter == 8:
                counter = 0
                out_string += '\n        '
            out_string += f'0x{byte:02x},'
            counter += 1
        out_string = out_string[:-1]
        out_string += "]\n"
        return out_string


def main(arguments):
    """main - main function

    :param:  arguments - straight up from sys.argv
    :return: None
    """
    parser = OptionParser()
    parser.add_option('-o', '--output', dest='out_file_name',
                      help='Output file name')
    parser.add_option('-i', '--input', dest='in_file_name',
                      help='Input file name')
    (options, args) = parser.parse_args(arguments)
    if options.out_file_name is None or options.in_file_name is None:
        print('# Failure - missing or improper arguments.')
    else:
        translator = Joyous(options)
        translator.run()


if __name__ == "__main__":
    main(sys.argv)
