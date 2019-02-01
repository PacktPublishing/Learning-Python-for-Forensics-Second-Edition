from helper import usb_lookup

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


def main(in_file):
    """
    Main function to handle operation
    :param in_file: Str - Path to setupapi log to analyze
    :return: list of USB data and list of headers for output
    """
    headers = ['Vendor ID', 'Vendor Name', 'Product ID',
	'Product Name', 'Revision', 'UID',
	'First Installation Date']
    data = []

    device_information = parse_setupapi(in_file)
    usb_ids = prep_usb_lookup()
    for device in device_information:
        parsed_info = parse_device_info(device)
        if isinstance(parsed_info, dict):
            parsed_info = get_device_names(usb_ids, parsed_info)
            data.append(parsed_info)
        else:
            pass
    return data, headers


def parse_setupapi(setup_log):
    """
    Read data from provided file for Device Install Events for
    USB Devices
    :param setup_log: str - Path to valid setup api log
    :return: tuple of str - Device name and date
    """
    device_list = list()
    unique_list = set()
    with open(setup_log) as in_file:
        for line in in_file:
            lower_line = line.lower()
            if 'device install (hardware initiated)' in \
                    lower_line and ('vid' in lower_line or
                                    'ven' in lower_line):
                device_name = line.split('-')[1].strip()
                date = next(in_file).split('start')[1].strip()
                if device_name not in unique_list:
                    device_list.append((device_name, date))
                    unique_list.add(device_name)

    return device_list


def parse_device_info(device_info):
    """
    Parses Vendor, Product, Revision and UID from a Setup API
    entry
    :param device_info: string of device information to parse
    :return: dictionary of parsed information or original string
    if error
    """
    # Initialize variables
    vid = ''
    pid = ''
    rev = ''
    uid = ''

    # Split string into segments on \\
    segments = device_info[0].split('\\')

    if 'usb' not in segments[0].lower():
        return None
        # Eliminate non-USB devices from output
        # May hide other storage devices

    for item in segments[1].split('&'):
        lower_item = item.lower()
        if 'ven' in lower_item or 'vid' in lower_item:
            vid = item.split('_', 1)[-1]
        elif 'dev' in lower_item or 'pid' in lower_item or \
                'prod' in lower_item:
            pid = item.split('_', 1)[-1]
        elif 'rev' in lower_item or 'mi' in lower_item:
            rev = item.split('_', 1)[-1]

    if len(segments) >= 3:
        uid = segments[2].strip(']')

    if vid != '' or pid != '':
        return {'Vendor ID': vid.lower(),
                'Product ID': pid.lower(),
                'Revision': rev,
                'UID': uid,
                'First Installation Date': device_info[1]}
    # Unable to parse data, returning whole string
    return device_info


def prep_usb_lookup(local_usb_ids=None):
    """
    Prepare the lookup of USB devices through accessing the most
    recent copy of the database at http://linux-usb.org/usb.ids
    or using the provided file and parsing it into a queriable
    dictionary format.
    """
    if local_usb_ids:
        usb_file = open(local_usb_ids, encoding='latin1')
    else:
        usb_file = usb_lookup.get_usb_file()
    return usb_lookup.parse_file(usb_file)


def get_device_names(usb_dict, device_info):
    """
    Query `usb_lookup.py` for device information based on VID/PID.
    :param usb_dict: Dictionary from usb_lookup.py of known
    devices.
    :param device_info: Dictionary containing 'Vendor ID' and
    'Product ID' keys and values.
    :return: original dictionary with 'Vendor Name' and
    'Product Name' keys and values
    """
    device_name = usb_lookup.search_key(
        usb_dict, [device_info['Vendor ID'],
            device_info['Product ID']])

    device_info['Vendor Name'] = device_name[0]
    device_info['Product Name'] = device_name[1]

    return device_info


def print_output(usb_information):
    """
    Print formatted information about USB Device
    :param usb_information: dictionary containing key/value
    data about each device or tuple of device information
    :return: None
    """
    print('{:-^15}'.format(''))

    if isinstance(usb_information, dict):
        for key_name, value_name in usb_information.items():
            print('{}: {}'.format(key_name, value_name))
    elif isinstance(usb_information, tuple):
        print('Device: {}'.format(usb_information[0]))
        print('Date: {}'.format(usb_information[1]))

