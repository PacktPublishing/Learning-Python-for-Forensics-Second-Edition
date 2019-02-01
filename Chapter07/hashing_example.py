"""Sample script to hash large files effiently."""
import argparse
import hashlib

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

HASH_LIBS = ['md5', 'sha1', 'sha256', 'sha512']
BUFFER_SIZE = 1024**3

parser = argparse.ArgumentParser()
parser.add_argument("FILE", help="File to hash")
parser.add_argument("-a", "--algorithm",
    help="Hash algorithm to use", choices=HASH_LIBS,
    default="sha512")
args = parser.parse_args()

alg = getattr(hashlib, args.algorithm)()

with open(args.FILE, 'rb') as input_file:

    buffer_data = input_file.read(BUFFER_SIZE)
    while buffer_data:
        alg.update(buffer_data)
        buffer_data = input_file.read(BUFFER_SIZE)

print(alg.hexdigest())
