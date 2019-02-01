"""UserAssist parser leveraging the YARP library."""
from __future__ import print_function
import argparse
import struct
import sys
import logging
import os
from Writers import xlsx_writer, csv_writer
from yarp import Registry

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
__date__ = '20181119'
__description__ = ('This scripts parses the UserAssist Key '
                   'from NTUSER.DAT.')

# KEYS will contain sub-lists of each parsed UserAssist (UA) key
KEYS = []


def main(registry, out_file):
	"""
	The main function handles main logic of script.
	:param registry: Registry Hive to process
	:param out_file: The output path and file
	:return: Nothing.
	"""
	if os.path.basename(registry).lower() != 'ntuser.dat':
		print(('[-] {} filename is incorrect (Should be '
               'ntuser.dat)').format(registry))
		logging.error('Incorrect file detected based on name')
		sys.exit(1)
	# Create dictionary of ROT-13 decoded UA key and its value
	apps = create_dictionary(registry)
	ua_type = parse_values(apps)

	if ua_type == 0:
		logging.info('Detected XP-based Userassist values.')

	else:
		logging.info(('Detected Win7-based Userassist values. '
		              'Contains Focus values.'))

	# Use .endswith string function to determine output type
	if out_file.lower().endswith('.xlsx'):
		xlsx_writer.excel_writer(KEYS, out_file)
	elif out_file.lower().endswith('.csv'):
		csv_writer.csv_writer(KEYS, out_file)
	else:
		print(('[-] CSV or XLSX extension not detected in '
		       'output. Writing CSV to current directory.'))
		logging.warning(('.csv or .xlsx output not detected. '
		                 'Writing CSV file to current '
						 'directory.'))
		csv_writer.csv_writer(KEYS, 'Userassist_parser.csv')


def create_dictionary(registry):
	"""
	The create_dictionary function creates a list of dictionaries
	where keys are the ROT-13 decoded app names and values are
	the raw hex data of said app.
	:param registry: Registry Hive to process
	:return: apps_list, A list containing dictionaries for
	each app
	"""
	try:
		# Open the registry file to be parsed
		registry_file = open(registry, "rb")
		reg = Registry.RegistryHive(registry_file)
	except (IOError, UnicodeDecodeError) as e:
		msg = 'Invalid NTUSER.DAT path or Registry ID.'
		print('[-]', msg)
		logging.error(msg)
		sys.exit(2)

	# Navigate to the UserAssist key
	ua_key = reg.find_key(
	('SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer'
	'\\UserAssist'))
	if ua_key is None:
		msg = 'UserAssist Key not found in Registry file.'
		print('[-]', msg)
		logging.error(msg)
		sys.exit(3)
	apps_list = []
	# Loop through each subkey in the UserAssist key
	for ua_subkey in ua_key.subkeys():
		# For each subkey in the UserAssist key, detect a subkey
        # called Count that has more than 0 values to parse.
		if(ua_subkey.subkey('Count') and
		ua_subkey.subkey('Count').values_count() > 0):
			apps = {}
			for v in ua_subkey.subkey('Count').values():
				if sys.version_info[0] == 2:
					apps[v.name().encode('utf-8').decode(
					'rot-13')] = v.data_raw()
				elif sys.version_info[0] == 3:
					import codecs
					enc = codecs.getencoder('rot-13')
					apps[enc(str(v.name()))[0]] = v.data_raw()

				apps_list.append(apps)
	return apps_list


def parse_values(data):
	"""
	The parse_values function uses struct to unpack the raw value
	data from the UA key
	:param data: A list containing dictionaries of UA
	application data
	:return: ua_type, based on the size of the raw data from
	the dictionary values.
	"""
	ua_type = -1
	msg = 'Parsing UserAssist values.'
	print('[+]', msg)
	logging.info(msg)

	for dictionary in data:
		for v in dictionary.keys():
			# WinXP based UA keys are 16 bytes
			if len(dictionary[v]) == 16:
				raw = struct.unpack('<2iq', dictionary[v])
				ua_type = 0
				KEYS.append({'Name': get_name(v), 'Path': v,
				'Session ID': raw[0], 'Count': raw[1],
				'Last Used Date (UTC)': raw[2],
				'Focus Time (ms)': '', 'Focus Count': ''})
			# Win7 based UA keys are 72 bytes
			elif len(dictionary[v]) == 72:
				raw = struct.unpack('<4i44xq4x', dictionary[v])
				ua_type = 1
				KEYS.append({'Name': get_name(v), 'Path': v,
				'Session ID': raw[0], 'Count': raw[1], 
				'Last Used Date (UTC)': raw[4],
				'Focus Time (ms)': raw[3],'Focus Count': raw[2]})
			else:
				# If the key is not WinXP or Win7 based -- ignore.
				msg = 'Ignoring {} value that is {} bytes'.format(
				str(v), str(len(dictionary[v])))
				print('[-]', msg)
				logging.info(msg)
				continue
	return ua_type


def get_name(full_name):
	"""
	the get_name function splits the name of the application
	returning the executable name and ignoring the
 	path details.
	:param full_name: the path and executable name
	:return: the executable name
	"""
	# Determine if '\\' and ':' are within the full_name
	if ':' in full_name and '\\' in full_name:
		# Find if ':' comes before '\\'
		if full_name.rindex(':') > full_name.rindex('\\'):
			# Split on ':' and return the last element 
			# (the executable)
			return full_name.split(':')[-1]
		else:
			# Otherwise split on '\\'
			return full_name.split('\\')[-1]
	# When just ':' or '\\' is in the full_name, split on
	# that item and return the last element (the executable)
	elif ':' in full_name:
		return full_name.split(':')[-1]
	else:
		return full_name.split('\\')[-1]


if __name__ == '__main__':
	parser = argparse.ArgumentParser(description=__description__,
									 epilog='Developed by ' +
									 __author__ + ' on ' +
									 __date__)
	parser.add_argument('REGISTRY', help='NTUSER Registry Hive.')
	parser.add_argument('OUTPUT',
	help='Output file (.csv or .xlsx)')
	parser.add_argument('-l', help='File path of log file.')

	args = parser.parse_args()

	if args.l:
		if not os.path.exists(args.l):
			os.makedirs(args.l)
		log_path = os.path.join(args.l, 'userassist_parser.log')
	else:
		log_path = 'userassist_parser.log'
	logging.basicConfig(filename=log_path, level=logging.DEBUG,
						format=('%(asctime)s | %(levelname)s | '
						        '%(message)s'), filemode='a')

	logging.info('Starting UserAssist_Parser')
	logging.debug('System ' + sys.platform)
	logging.debug('Version ' + sys.version)
	main(args.REGISTRY, args.OUTPUT)
