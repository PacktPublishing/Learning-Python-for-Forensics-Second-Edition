from __future__ import print_function
import sys
if sys.version_info[0] == 2:
	import unicodecsv as csv
elif sys.version_info[0] == 3:
	import csv
from datetime import datetime, timedelta
import logging

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

def csv_writer(data, out_file):
	"""
	The csv_writer function writes the parsed UA data to a csv
	file
	:param data: the list of lists containing parsed UA data
	:param out_file: the desired output directory and filename
	for the csv file
	:return: Nothing
	"""
	print('[+] Writing CSV output.')
	logging.info('Writing CSV to ' + out_file + '.')
	headers = ['ID', 'Name', 'Path', 'Session ID', 'Count',
	'Last Used Date (UTC)', 'Focus Time (ms)', 'Focus Count']
	
	if sys.version_info[0] == 2:
		csvfile = open(out_file, "wb")
	elif sys.version_info[0] == 3:
		csvfile = open(out_file, "w", newline='',
		encoding='utf-8')
		
	with csvfile:
		writer = csv.DictWriter(csvfile, fieldnames=headers,
		extrasaction='ignore')
		# Writes the header from list supplied to fieldnames
		# keyword argument
		writer.writeheader()

		for i, dictionary in enumerate(data):
			# Insert the 'ID' value to each dictionary in the
		    # list. Add 1 to start ID at 1 instead of 0.
			dictionary['ID'] = i + 1
			# Convert the FILETIME object in the fourth index to
            # human readable value
			dictionary['Last Used Date (UTC)'] = file_time(
			dictionary['Last Used Date (UTC)'])
			writer.writerow(dictionary)

		csvfile.flush()
		csvfile.close()
		msg = 'Completed writing CSV file. Program exiting successfully.'
		print('[*]', msg)
		logging.info(msg)


def file_time(ft):
	"""
	The fileTime function converts Windows FILETIME objects into
	human readable value
	:param ft: the FILETIME to convert
	:return: date_str, the human readable datetime value
	"""
	if ft is not None and ft != 0:
		return datetime(1601, 1, 1) + timedelta(microseconds=ft / 10)
	else:
		return 0
