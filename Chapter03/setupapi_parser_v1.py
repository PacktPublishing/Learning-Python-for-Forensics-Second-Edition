"""First iteration of the setupapi.dev.log parser."""
from __future__ import print_function
from io import open

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


def main():
    """
    Primary controller for script.
    :return: None
    """
    # Insert your own path to your sample setupapi.dev.log here.
    file_path = 'setupapi.dev.log'

    # Print version information when the script is run
    print('='*22)
    print('SetupAPI Parser, v', __date__)
    print('='*22)
    parse_setupapi(file_path)


def parse_setupapi(setup_file):
    """
    Interpret the file
    :param setup_file: path to the setupapi.dev.log
    :return: None
    """
    in_file = open(setup_file)
    data = in_file.readlines()

    for i, line in enumerate(data):
        if 'device install (hardware initiated)' in line.lower():
            device_name = data[i].split('-')[1].strip()
            date = data[i+1].split('start')[1].strip()
            print_output(device_name, date)
    in_file.close()


def print_output(usb_name, usb_date):
    """
    Print the information discovered
    :param usb_name: String USB Name to print
    :param usb_date: String USB Date to print
    :return: None
    """
    print('Device: {}'.format(usb_name))
    print('First Install: {}'.format(usb_date))


if __name__ == '__main__':
    # Run the program
    main()
