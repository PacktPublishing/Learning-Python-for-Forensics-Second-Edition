"""Parse a SQLite WAL file to recover table data."""
from __future__ import print_function
import binascii
import logging
import os
import re
import struct
from collections import namedtuple


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


def main(wal_file, **kwargs):
    """
    The main function parses the header of the input file and
    identifies the WAL file. It then splits the file into the
    appropriate frames and send them for processing. After
    processing, if applicable, the regular expression modules are
    ran. Finally the raw data output is written to a CSV file.
    :param wal_file: The filepath to the WAL file to be processed
    :return: Nothing.
    """
    wal_attributes = {'size': os.path.getsize(wal_file),
    'header': {}, 'frames': {}}
    with open(wal_file, 'rb') as wal:

        # Parse 32-byte WAL header.
        header = wal.read(32)

        # If file is less than 32 bytes long: exit wal_crawler.
        try:
            wal_attributes['header'] = dict_helper(header,'>4s7i',
            namedtuple('struct',
            'magic format pagesize checkpoint '
            'salt1 salt2 checksum1 checksum2'))
        except struct.error as e:
            logging.error('[-]', e.message + '. Exiting..')
            raise TypeError

        # Do not proceed in the program if the input file is not a
        # WAL file.
        magic_hex = binascii.hexlify(
        wal_attributes['header']['magic']).decode('utf-8')
        if magic_hex != "377f0682" and magic_hex != "377f0683":
            logging.error(('[-] File does not have appropriate signature '
            'for WAL file. Exiting...'))
            raise TypeError


        # Calculate number of frames.
        frames = int((
        wal_attributes['size'] - 32) / (
        wal_attributes['header']['pagesize'] + 24))

        # Parse frames in WAL file.
        for x in range(frames):

            # Parse 24-byte WAL frame header.
            wal_attributes['frames'][x] = {}
            frame_header = wal.read(24)
            wal_attributes['frames'][x]['header'] = dict_helper(
            frame_header, '>6i', namedtuple('struct',
            'pagenumber commit salt1'
            ' salt2 checksum1'
            ' checksum2'))

            # Parse pagesize WAL frame
            frame = wal.read(wal_attributes['header']['pagesize'])
            frame_parser(wal_attributes, x, frame)

    # Write WAL data to CSV file.
    headers = ['File', 'Frame', 'Salt-1', 'Salt-2',
    'Frame Offset', 'Cell', 'Cell Offset', 'ROWID', 'Data']
    results = []
    for frame in wal_attributes['frames']:
        if wal_attributes['frames'][frame]['cells'] is not None:
            for cell in wal_attributes['frames'][frame]['cells']:
                if ('data' in wal_attributes['frames'][frame]['cells'][cell].keys() and
                len(wal_attributes['frames'][frame]['cells'][cell]['data']) > 0):
                    frame_offset = 32 + (frame * wal_attributes['header']['pagesize']) + (frame * 24)
                    cell_offset = frame_offset + 24 + wal_attributes['frames'][frame]['cells'][cell]['offset']
                    results.append({'File': wal_file,
                    'Frame': frame,
                    'Salt-1': wal_attributes['frames'][frame]['header']['salt1'],
                    'Salt-2': wal_attributes['frames'][frame]['header']['salt2'],
                    'Frame Offset': frame_offset,
                    'Cell': cell, 'Cell Offset': cell_offset,
                    'ROWID': wal_attributes['frames'][frame]['cells'][cell]['rowid'],
                    'Data': wal_attributes['frames'][frame]['cells'][cell]['data']})

    return results, headers


def frame_parser(wal_dict, x, frame):
    """
    The frame_parser function processes WAL frames.
    :param wal_dict: The dictionary containing parsed WAL objects.
    :param x: An integer specifying the current frame.
    :param frame: The content within the frame read from the WAL
    file.
    :return: Nothing.
    """

    # Parse 8-byte WAL page header
    page_header = frame[0:8]
    wal_dict['frames'][x]['page_header'] = dict_helper(
    page_header, '>b3hb', namedtuple('struct',
    'type freeblocks cells offset'
    ' fragments'))
    # Only want to parse 0x0D B-Tree Leaf Cells
    if wal_dict['frames'][x]['page_header']['type'] != 13:
        logging.info(('Found a non-Leaf Cell in frame {}. Popping '
        'frame from dictionary').format(x))
        wal_dict['frames'].pop(x)
        return
    # Parse offsets for "X" cells
    cells = wal_dict['frames'][x]['page_header']['cells']
    wal_dict['frames'][x]['cells'] = {}

    for y in range(cells):
        start = 8 + (y * 2)
        wal_dict['frames'][x]['cells'][y] = {}

        wal_dict['frames'][x]['cells'][y] = dict_helper(
        frame[start: start + 2], '>h', namedtuple(
        'struct', 'offset'))

        # Parse cell content
        cell_parser(wal_dict, x, y, frame)


def cell_parser(wal_dict, x, y, frame):
    """
    The cell_parser function processes WAL cells.
    :param wal_dict: The dictionary containing parsed WAL objects.
    :param x: An integer specifying the current frame.
    :param y: An integer specifying the current cell.
    :param frame: The content within the frame read from the WAL
    file.
    :return: Nothing.
    """
    index = 0
    # Create alias to cell_root to shorten navigating the WAL
    # dictionary structure.
    cell_root = wal_dict['frames'][x]['cells'][y]
    cell_offset = cell_root['offset']

    # Parse the payload length and rowID Varints.
    try:
        payload_len, index_a = single_varint(
        frame[cell_offset:cell_offset + 9])
        row_id, index_b = single_varint(
        frame[cell_offset + index_a: cell_offset + index_a + 9])
    except ValueError:
        logging.warn(('Found a potential three-byte or greater '
        'varint in cell {} from frame {}').format(y, x))
        return

    # Update the index. Following the payload length and rowID is
    # the 1-byte header length.
    cell_root['payloadlength'] = payload_len
    cell_root['rowid'] = row_id
    index += index_a + index_b
    cell_root['headerlength'] = struct.unpack('>b',
    frame[cell_offset + index: cell_offset + index + 1])[0]

    # Update the index with the 1-byte header length. Next process
    # each Varint in "headerlength" - 1 bytes.
    index += 1
    try:
        types, index_a = multi_varint(
        frame[cell_offset + index:cell_offset+index+cell_root['headerlength']-1])
    except ValueError:
        logging.warn(('Found a potential three-byte or greater '
        'varint in cell {} from frame {}').format(y, x))
        return
    cell_root['types'] = types
    index += index_a

    # Immediately following the end of the Varint headers begins
    # the actual data described by the headers. Process them using
    # the typeHelper function.
    diff = cell_root['payloadlength'] - cell_root['headerlength']
    cell_root['data'] = type_helper(cell_root['types'],
    frame[cell_offset + index: cell_offset + index + diff])


def dict_helper(data, format, keys):
    """
    The dict_helper function creates an OrderedDictionary from
    a struct tuple.
    :param data: The data to be processed with struct.
    :param format: The struct format string.
    :param keys: A string of the keys for the values in the struct
    tuple.
    :return: An OrderedDictionary with descriptive keys of
    struct-parsed values.
    """
    return keys._asdict(keys._make(struct.unpack(format, data)))


def single_varint(data, index=0):
    """
    The single_varint function processes a Varint and returns the
    length of that Varint.
    :param data: The data containing the Varint (maximum of 9
    bytes in length as that is the maximum size of a Varint).
    :param index: The current index within the data.
    :return: varint, the processed varint value,
    and index which is used to identify how long the Varint was.
    """

    # If the decimal value is => 128 -- then first bit is set and
    # need to process next byte.
    if ord(data[index:index+1]) >= 128:
        # Check if there is a three or more byte varint
        if ord(data[index + 1: index + 2]) >= 128:
            raise ValueError
        varint = (ord(data[index:index+1]) - 128) * 128 + ord(
        data[index + 1: index + 2])
        index += 2
        return varint, index

    # If the decimal value is < 128 -- then first bit is not set
    # and is the only byte of the Varint.
    else:
        varint = ord(data[index:index+1])
        index += 1
        return varint, index


def multi_varint(data):
    """
    The multi_varint function is similar to the single_varint
    function. The difference is that it takes a range of data
    and finds all Varints within it.
    :param data: The data containing the Varints.
    :return: varints, a list containing the processed varint
    values, and index which is used to identify how long the
    Varints were.
    """
    varints = []
    index = 0

    # Loop forever until all Varints are found by repeatedly
    # calling singleVarint.
    while len(data) != 0:
        varint, index_a = single_varint(data)
        varints.append(varint)
        index += index_a
        # Shorten data to exclude the most recent Varint.
        data = data[index_a:]

    return varints, index


def type_helper(types, data):
    """
    The type_helper function decodes the serial type of the
    Varints in the WAL file.
    :param types: The processed values of the Varints.
    :param data: The raw data in the cell that needs to be
    properly decoded via its varint values.
    :return: cell_data, a list of the processed data.
    """
    cell_data = []
    index = 0

    # Value of type dictates how the data should be processed.
    # See serial type table in chapter for list of possible
    # values.
    for type in types:

        if type == 0:
            cell_data.append('NULL (RowId?)')
        elif type == 1:
            cell_data.append(struct.unpack('>b',
            data[index:index + 1])[0])
            index += 1
        elif type == 2:
            cell_data.append(struct.unpack('>h',
            data[index:index + 2])[0])
            index += 2
        elif type == 3:
            # Struct does not support 24-bit integer
            cell_data.append(int(binascii.hexlify(
            data[index:index + 3]).decode('utf-8'), 16))
            index += 3
        elif type == 4:
            cell_data.append(struct.unpack(
            '>i', data[index:index + 4])[0])
            index += 4
        elif type == 5:
            # Struct does not support 48-bit integer
            cell_data.append(int(binascii.hexlify(
            data[index:index + 6]).decode('utf-8'), 16))
            index += 6
        elif type == 6:
            cell_data.append(struct.unpack(
            '>q', data[index:index + 8])[0])
            index += 8
        elif type == 7:
            cell_data.append(struct.unpack(
            '>d', data[index:index + 8])[0])
            index += 8
        # Type 8 == Constant 0 and Type 9 == Constant 1. Neither of these take up space in the actual data.
        elif type == 8:
            cell_data.append(0)
        elif type == 9:
            cell_data.append(1)
        # Types 10 and 11 are reserved and currently not implemented.
        elif type > 12 and type % 2 == 0:
            b_length = int((type - 12) / 2)
            cell_data.append(data[index:index + b_length])
            index += b_length
        elif type > 13 and type % 2 == 1:
            s_length = int((type - 13) / 2)
            cell_data.append(
            data[index:index + s_length].decode('utf-8'))
            index += s_length

        else:
            msg = 'Unexpected serial type: {}'.format(type)
            logging.error(msg)

    return cell_data