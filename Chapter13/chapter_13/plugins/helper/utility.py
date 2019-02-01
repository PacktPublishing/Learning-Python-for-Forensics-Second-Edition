import binascii
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


def check_header(filename, headers, size):
	"""
	The check_header function reads a supplied size of the file
	and checks against known signatures to determine the file
	type.
	:param filename: The name of the file.
	:param headers: A list of known file signatures for the
	file type(s).
	:param size: The amount of data to read from the file for
	signature verification.
	:return: Boolean, True if the signatures match;
	otherwise, False.
	"""
	with open(filename, 'rb') as infile:
		header = infile.read(size)
		hex_header = binascii.hexlify(header).decode('utf-8')
		for signature in headers:
			if hex_header == signature:
				return True
			else:
				pass
		logging.warn(('The signature for {} ({}) does not match '
		'known signatures: {}').format(
		filename, hex_header, headers))
		return False


def convert_size(size):
	"""
	The convert_size function converts an integer representing
	bytes into a human-readable format.
	:param size: The size in bytes of a file
	:return: The human-readable size.
	"""
	sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB']
	index = 0
	while size > 1024:
		size /= 1024.
		index += 1
	return '{:.2f} {}'.format(size, sizes[index])


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