from __future__ import print_function
import xlsxwriter

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

ALPHABET = [chr(i) for i in range(ord('A'), ord('Z') + 1)]


def writer(output, headers, output_data, **kwargs):
    """
    The writer function writes excel output for the framework
    :param output: the output filename for the excel spreadsheet
    :param headers: the name of the spreadsheet columns
    :param output_data: the data to be written to the excel
    spreadsheet
    :return: Nothing
    """
    wb = xlsxwriter.Workbook(output)

    if headers is None:
        print('[-] Received empty headers... \n'
        '[-] Skipping writing output.')
        return

    if len(headers) <= 26:
        title_length = ALPHABET[len(headers) - 1]
    else:
        title_length = 'Z'

    ws = add_worksheet(wb, title_length)

    if 'recursion' in kwargs.keys():
        for i, data in enumerate(output_data):
            if i > 0:
                ws = add_worksheet(wb, title_length)
            cell_length = len(data)
            tmp = []
            for dictionary in data:
                tmp.append(
                    [str(dictionary[x]) if x in dictionary.keys() else '' for x in headers]
                )

            ws.add_table(
            'A3:' + title_length + str(3 + cell_length),
            {'data': tmp,
            'columns': [{'header': x} for x in headers]})

    else:
        cell_length = len(output_data)
        tmp = []
        for data in output_data:
            tmp.append([str(data[x]) if x in data.keys() else '' for x in headers])
        ws.add_table(
        'A3:' + title_length + str(3 + cell_length),
        {'data': tmp,
        'columns': [{'header': x} for x in headers]})

    wb.close()


def add_worksheet(wb, length, name=None):
    """
    The add_worksheet function creates a new formatted worksheet
    in the workbook
    :param wb: The workbook object
    :param length: The range of rows to merge
    :param name: The name of the worksheet
    :return: ws, the worksheet
    """
    title_format = wb.add_format({'bold': True,
    'font_color': 'black', 'bg_color': 'white', 'font_size': 30,
    'font_name': 'Arial', 'align': 'center'})
    ws = wb.add_worksheet(name)

    ws.merge_range('A1:' + length + '1', 'XYZ Corp',
    title_format)
    ws.merge_range('A2:' + length + '2', 'Case ####',
    title_format)
    return ws