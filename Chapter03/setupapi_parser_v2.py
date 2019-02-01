"""Second iteration of the setupapi.dev.log parser."""
from __future__ import print_function
import argparse
from io import open
import os
import sys

"""
MIT License
Copyright (c) 2018 Chapin Bryce, Preston Miller
Please share comments and questions at:
  https://github.com/PythonForensics/Learning-Python-for-Forensics
  or email pyforcookbook@gmail.com

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
"""

__authors__ = ["Chapin Bryce", "Preston Miller"]
__date__ = 20181027
__description__ = """This scripts reads a Windows 7 Setup API
    log and prints USB Devices to the user"""


def main(in_file):
    """
    Main function to handle operation
    :param in_file: string path to Windows 7 setupapi.dev.log
    :return: None
    """
    if os.path.isfile(in_file):
        print('{:=^22}'.format(''))
        print('{} {}'.format('SetupAPI Parser, v', __date__))
        print('{:=^22} \n'.format(''))
        device_information = parse_setupapi(in_file)
        for device in device_information:
            print_output(device[0], device[1])
    else:
        print('Input is not a file.')
        sys.exit(1)


def parse_setupapi(setup_log):
    """
    Read data from provided file for Device Install Events for
        USB Devices
    :param setup_log: str - Path to valid setup api log
    :return: list of tuples - Tuples contain device name and date
        in that order
    """
    device_list = list()
    with open(setup_log) as in_file:
        for line in in_file:
            lower_line = line.lower()
            # if 'Device Install (Hardware initiated)' in line:
            if 'device install (hardware initiated)' in \
                    lower_line and ('ven' in lower_line or
                                    'vid' in lower_line):
                device_name = line.split('-')[1].strip()

                if 'usb' not in device_name.split(
                        '\\')[0].lower():
                    continue
                    # Remove most non-USB devices
                    # This can remove records that may be
                    # relevant so please always validate that
                    # the data reduction does not remove results
                    # of interest to you.

                date = next(in_file).split('start')[1].strip()
                device_list.append((device_name, date))

    return device_list


def print_output(usb_name, usb_date):
    """
    Print the information discovered
    :param usb_name: String USB Name to print
    :param usb_date: String USB Date to print
    :return: None
    """
    print('Device: {}'.format(usb_name))
    print('First Install: {}\n'.format(usb_date))


if __name__ == '__main__':
    # Run this code if the script is run from the command line.
    parser = argparse.ArgumentParser(
        description=__description__,
        epilog='Built by {}. Version {}'.format(
            ", ".join(__authors__), __date__),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument('IN_FILE',
                        help='Windows 7 SetupAPI file')
    args = parser.parse_args()

    # Run main program
    main(args.IN_FILE)
