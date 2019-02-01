"""Script to convert UNIX timestamps."""
from __future__ import print_function
import datetime
import sys

if sys.version_info[0] == 3:
    get_input = input
elif sys.version_info[0] == 2:
    get_input = raw_input
else:
    raise NotImplementedError(
        "Unsupported version of Python used.")

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
__description__ = """Convert unix formatted timestamps (seconds
    since Epoch [1970-01-01 00:00:00]) to human readable."""


def main():
    unix_ts = int(get_input('Unix timestamp to convert:\n>> '))
    print(unix_converter(unix_ts))


def unix_converter(timestamp):
    date_ts = datetime.datetime.utcfromtimestamp(timestamp)
    return date_ts.strftime('%m/%d/%Y %I:%M:%S %p')

if __name__ == '__main__':
    main()
