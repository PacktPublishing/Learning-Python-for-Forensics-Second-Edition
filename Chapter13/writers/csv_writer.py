from __future__ import print_function
import sys
import os
if sys.version_info[0] == 2:
    import unicodecsv as csv
elif sys.version_info[0] == 3:
    import csv

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


def writer(output, headers, output_data, **kwargs):
    """
    The writer function uses the csv.DictWriter module to write
    list(s) of dictionaries. The DictWriter can take a fieldnames
    argument, as a list, which represents the desired order of
    columns.
    :param output: The name of the output CSV.
    :param headers: A list of keys in the dictionary that
    represent the desired order of columns in the output.
    :param output_data: The list of dictionaries containing
    embedded metadata.
    :return: None
    """

    if sys.version_info[0] == 2:
        csvfile = open(output, "wb")
    elif sys.version_info[0] == 3:
        csvfile = open(output, "w", newline='',
        encoding='utf-8')

    with csvfile:
        # We use DictWriter instead of writer to write
        # dictionaries to CSV.
        w = csv.DictWriter(csvfile, fieldnames=headers,
        extrasaction='ignore')

        # Writerheader writes the header based on the supplied
        # headers object
        try:
            w.writeheader()
        except TypeError:
            print(('[-] Received empty headers...\n'
            '[-] Skipping writing output.'))
            return

        if 'recursion' in kwargs.keys():
            for l in output_data:
                for data in l:
                    if data:
                        w.writerow(data)
        else:
            for data in output_data:
                if data:
                    w.writerow(data)