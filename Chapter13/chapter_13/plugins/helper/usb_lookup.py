"""Updated USB Lookup script based on the version found in Chapter 2."""
from __future__ import print_function
import argparse
import sys
try:
    from urllib2 import urlopen
except ImportError:
    from urllib.request import urlopen

"""
MIT License
Copyright (c) 2018 Chapin Bryce, Preston Miller
Please share comments and questions at:
    https://github.com/PythonForensics/Learning-Python-for-Forensics
    or email pyforcookbook@gmail.com

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

def main(vid, pid, ids_file=None):
    """
    Main function to control operation. Requires arguments passed as VID PID
    on the command line. If discovered in data set, the common names will be
    printed to stdout
    :return: None
    """
    if ids_file:
        usb_file = open(ids_file, encoding='latin1')
    else:
        usb_file = get_usb_file()
    usbs = parse_file(usb_file)
    results = search_key(usbs, (vid, pid))
    print("Vendor: {}\nProduct: {}".format(results[0], results[1]))


def get_usb_file():
    """
    Retrieves USB.ids database from the web.
    """
    url = 'http://www.linux-usb.org/usb.ids'
    return urlopen(url)


def parse_file(usb_file):
    """
    Parses the USB.ids file. If this is run offline, please
	download the USB.ids and pass the open file to this function.
    ie: parse_file(open('path/to/USB.ids', 'r'))
    :return: dictionary of entires for querying
    """
    usbs = {}
    curr_id = ''
    for line in usb_file:
        if isinstance(line, bytes):
            line = line.decode('latin-1')
        if line.startswith('#') or line in ('\n', '\t'):
            continue
        else:
            if not line.startswith('\t') and (line[0].isdigit() or
                                              line[0].islower()):
                uid, name = get_record(line.strip())
                curr_id = uid
                usbs[uid] = [name.strip(), {}]
            elif line.startswith('\t') and line.count('\t') == 1:
                uid, name = get_record(line.strip())
                usbs[curr_id][1][uid] = name.strip()
    return usbs


def get_record(record_line):
    """
    Split records out by dynamic position. By finding the space,
	we can determine the location to split the record for
	extraction. To learn more about this, uncomment the print
	statements and see what the code is doing behind the scenes!
    """
    # print("Line: {}".format(record_line))
    split = record_line.find(' ')
    # print("Split: {}".format(split))
    record_id = record_line[:split]
    # print("Record ID: ".format(record_id))
    record_name = record_line[split + 1:]
    # print("Record Name: ".format(record_name))
    return record_id, record_name


def search_key(usb_dict, ids):
    """
    Compare provided IDs to the built USB dictionary. If found,
	it will return the common name, otherwise returns the string
	"unknown".
    """
    vendor_key = ids[0]
    product_key = ids[1]

    vendor, vendor_data = usb_dict.get(vendor_key, ['unknown', {}])
    product = 'unknown'
    if vendor != 'unknown':
        product = vendor_data.get(product_key, 'unknown')

    return vendor, product
