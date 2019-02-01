"""Parse a SQLite WAL file to recover table data."""
from __future__ import print_function
import argparse
import binascii
import logging
import os
import re
import struct
import sys
from collections import namedtuple
if sys.version_info[0] == 2:
	import unicodecsv as csv
elif sys.version_info[0] == 3:
	import csv

from tqdm import trange

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


__author__ = 'Preston Miller & Chapin Bryce'
__date__ = '20181125'
__description__ = ('This scripts processes SQLite '
'"Write Ahead Logs" and extracts database entries that may '
'contain deleted records or records that have not yet been added '
'to the main database.')


def main(wal_file, output_dir, **kwargs):
	"""
	The main function parses the header of the input file and
	identifies the WAL file. It then splits the file into the
	appropriate frames and send them for processing. After
	processing, if applicable, the regular expression modules are
	ran. Finally the raw data output is written to a CSV file.
	:param wal_file: The filepath to the WAL file to be processed
	:param output_dir: The directory to write the CSV report to.
	:return: Nothing.
	"""
	msg = 'Identifying and parsing file header'
	print('[+]', msg)
	logging.info(msg)

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
			logging.error('STRUCT ERROR:', e.message)
			print('[-]', e.message + '. Exiting..')
			sys.exit(2)

		# Do not proceed in the program if the input file is not a
		# WAL file.
		magic_hex = binascii.hexlify(
		wal_attributes['header']['magic']).decode('utf-8')
		if magic_hex != "377f0682" and magic_hex != "377f0683":
			logging.error(('Magic mismatch, expected 0x377f0682 '
			'or 0x377f0683 | received {}'.format(magic_hex)))
			print(('[-] File does not have appropriate signature '
			'for WAL file. Exiting...'))
			sys.exit(3)

		logging.info('File signature matched.')
		logging.info('Processing WAL file.')

		# Calculate number of frames.
		frames = int((
		wal_attributes['size'] - 32) / (
		wal_attributes['header']['pagesize'] + 24))
		print('[+] Identified', frames, 'Frames.')

		# Parse frames in WAL file. Create progress bar using
		# trange(frames) which is an alias for tqdm(xrange(frames)).
		print('[+] Processing frames...')
		for x in trange(frames):

			# Parse 24-byte WAL frame header.
			wal_attributes['frames'][x] = {}
			frame_header = wal.read(24)
			wal_attributes['frames'][x]['header'] = dict_helper(
			frame_header, '>6i', namedtuple('struct',
			'pagenumber commit salt1'
			' salt2 checksum1'
			' checksum2'))
			# Parse pagesize WAL frame.
			frame = wal.read(wal_attributes['header']['pagesize'])
			frame_parser(wal_attributes, x, frame)

		# Run regular expression functions.
		if kwargs['m'] or kwargs['r']:
			regular_search(wal_attributes, kwargs)

		# Write WAL data to CSV file.
		csv_writer(wal_attributes, output_dir)


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
	print('[+] Identified', cells, 'cells in frame', x)
	print('[+] Processing cells...')

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
			print('[-]', msg)
			logging.error(msg)

	return cell_data


def csv_writer(data, output_dir):
	"""
	The csv_writer function writes frame, cell, and data to a CSV
	output file.
	:param data: The dictionary containing the parsed WAL file.
	:param output_dir: The directory to write the CSV report to.
	:return: Nothing.
	"""
	headers = ['Frame', 'Salt-1', 'Salt-2', 'Frame Offset',
	'Cell', 'Cell Offset', 'ROWID', 'Data']

	out_file = os.path.join(output_dir, 'wal_crawler.csv')
	
	if sys.version_info[0] == 2:
		csvfile = open(out_file, "wb")
	elif sys.version_info[0] == 3:
		csvfile = open(out_file, "w", newline='',
		encoding='utf-8')
		
	with csvfile:
		writer = csv.writer(csvfile)
		writer.writerow(headers)

		for frame in data['frames']:

			for cell in data['frames'][frame]['cells']:

				# Only write entries for cells that have data.
				if ('data' in data['frames'][frame]['cells'][cell].keys() and
				len(data['frames'][frame]['cells'][cell]['data']) > 0):
					# Convert relative frame and cell offsets to
					# file offsets.
					frame_offset = 32 + (
					frame * data['header']['pagesize']) + (
					frame * 24)
					cell_offset = frame_offset + 24 + data['frames'][frame]['cells'][cell]['offset']

					# Cell identifiers include the frame #, 
					# salt-1, salt-2, frame offset,
					# cell #, cell offset, and cell rowID.
					cell_identifiers = [frame, data['frames'][frame]['header']['salt1'],
										data['frames'][frame]['header']['salt2'],
										frame_offset, cell, cell_offset,
										data['frames'][frame]['cells'][cell]['rowid']]

					# Write the cell_identifiers and actual data
					# within the cell
					writer.writerow(
					cell_identifiers + data['frames'][frame]['cells'][cell]['data'])

				else:
					continue

		csvfile.flush()
		csvfile.close()


def regular_search(data, options):
	"""
	The regular_search function performs either default regular
	expression searches for personal information or custom
	searches based on a supplied regular expression string.
	:param data: The dictionary containing the parsed WAL file.
	:param options: The options dictionary contains custom or
	pre-determined regular expression searching
	:return: Nothing.
	"""
	msg = 'Initializing regular expression module.'
	print('\n{}\n[+]'.format('='*20), msg)
	logging.info(msg)
	if options['r'] and not options['m']:
		regexp = {'Custom': options['r']}
	else:
		# Default regular expression modules include: Credit card
		# numbers, SSNs, Phone numbers, URLs, IP Addresses.
		regexp = {'Visa Credit Card': r'^4\d{3}([\	\-]?)\d{4}\1\d{4}\1\d{4}$',
				  'SSN': r'^\d{3}-\d{2}-\d{4}$',
				  'Phone Number': r'^\d{3}([\ \. \-]?)\d{3}\1\d{4}$',
				  'URL': r"(http[s]?://)|(www.)(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+",
				  'IP Address': r'^\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}$'}

		if options['r']:
			regexp['Custom'] = options['r']

	# Must compile each regular expression before seeing if any
	# data "matches" it.
	for exp in regexp.keys():
		reg_exp = re.compile(regexp[exp])

		for frame in data['frames']:

			for cell in data['frames'][frame]['cells']:

				for datum in range(len(
				data['frames'][frame]['cells'][cell]['data'])):
					# TypeError will occur for non-string objects
					# such as integers.
					try:
						match = reg_exp.match(
						data['frames'][frame]['cells'][cell]['data'][datum])
					except TypeError:
						continue
					# Print any successful match to user.
					if match:
						msg = '{}: {}'.format(exp,
						data['frames'][frame]['cells'][cell]['data'][datum])
						print('[*]', msg)
	print('='*20)


if __name__ == '__main__':

	parser = argparse.ArgumentParser(description=__description__,
									 epilog='Developed by ' +
									 __author__ + ' on ' +
									 __date__)

	parser.add_argument('WAL', help='SQLite WAL file')
	parser.add_argument('OUTPUT_DIR', help='Output Directory')
	parser.add_argument('-r', help='Custom regular expression')
	parser.add_argument('-m', help='Run regular expression module',
	action='store_true')
	parser.add_argument('-l', help='File path of log file')
	args = parser.parse_args()

	if args.l:
		if not os.path.exists(args.l):
			os.makedirs(args.l)
		log_path = os.path.join(args.l, 'wal_crawler.log')
	else:
		log_path = 'wal_crawler.log'
	logging.basicConfig(filename=log_path, level=logging.DEBUG,
						format=('%(asctime)s | %(levelname)s | '
						        '%(message)s'), filemode='a')

	logging.info('Starting Wal_Crawler')
	logging.debug('System ' + sys.platform)
	logging.debug('Version ' + sys.version)

	if not os.path.exists(args.OUTPUT_DIR):
		os.makedirs(args.OUTPUT_DIR)

	if os.path.exists(args.WAL) and os.path.isfile(args.WAL):
		main(args.WAL, args.OUTPUT_DIR, r=args.r, m=args.m)
	else:
		msg = 'Supplied WAL file does not exist or is not a file'
		print('[-]', msg)
		logging.error(msg)
		sys.exit(1)