"""Sample argparse example."""
from __future__ import print_function
import argparse

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
__description__ = "Argparse command-line parser sample"


def main(args):
    print(args)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=__description__,
        epilog='Built by {}. Version {}'.format(
            ", ".join(__authors__), __date__),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    # Add positional required arguments
    parser.add_argument('timezone', help='timezone to apply')

    # Add non-positional required argument
    parser.add_argument('--source',
        help='source information', required=True)

    # Add optional arguments, allowing shorthand argument
    parser.add_argument('-l', '--log', help='Path to log file')

    # Using actions
    parser.add_argument('--no-email',
        help='disable emails', action="store_false")
    parser.add_argument('--send-email',
        help='enable emails', action="store_true")
    # Append values for each argument instance.
    parser.add_argument('--emails',
        help='email addresses to notify', action="append")
    # Count the number of instances. i.e. -vvv
    parser.add_argument('-v', help='add verbosity', action='count')

    # Defaults
    parser.add_argument('--length', default=55, type=int)
    parser.add_argument('--name', default='Alfred', type=str)

    # Handling Files
    parser.add_argument('input_file', type=argparse.FileType('r'))
    parser.add_argument('output_file', type=argparse.FileType('w'))

    # Allow only specified choices
    parser.add_argument('--file-type',
        choices=['E01', 'RAW', 'Ex01'])

    # Parsing defined arguments
    arguments = parser.parse_args()
    main(arguments)
