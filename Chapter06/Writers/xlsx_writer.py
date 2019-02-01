from __future__ import print_function
import xlsxwriter
from operator import itemgetter
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


def excel_writer(data, out_file):
    """
    The excel_writer function handles the main logic of writing
	the excel output
    :param data: the list of lists containing parsed UA data
    :param out_file: the desired output directory and filename
	for the excel file
    :return: Nothing
    """
    print('[+] Writing XLSX output.')
    logging.info('Writing XLSX to ' + out_file + '.')
    headers = ['Name', 'Path', 'Session ID', 'Count',
	'Last Used Date (UTC)', 'Focus Time (ms)', 'Focus Count']
    wb = xlsxwriter.Workbook(out_file)
    title_format = wb.add_format({'bold': True,
	'font_color': 'white', 'bg_color': 'black', 'font_size': 30,
	'font_name': 'Calibri', 'align': 'center'})

    # A temporary list that will store dictionary values
    tmp_list = []
    for dictionary in data:
        # Adds dictionary values to a list ordered by the headers
		# Adds an empty string is the key does not exist
        tmp_list.append([dictionary.get(x, '') for x in headers])

    dashboard_writer(wb, tmp_list, title_format)
    userassist_writer(wb, tmp_list, headers, title_format)

    wb.close()
    msg =('Completed writing XLSX file. '
	      'Program exiting successfully.')
    print('[*]', msg)
    logging.info(msg)


def dashboard_writer(workbook, data, ua_format):
    """
    the dashboard_writer function creates the 'Dashboard'
	worksheet, table, and graphs
    :param workbook: the excel workbook object
    :param data: the list of lists containing parsed UA data
    :param ua_format: the format object for the title and
	subtitle row
    :return: Nothing
    """
    dashboard = workbook.add_worksheet('Dashboard')
    dashboard.merge_range('A1:Q1', 'XYZ Corp', ua_format)
    dashboard.merge_range('A2:Q2', 'Dashboard', ua_format)

    # The format to use to convert datetime object into a human
	# readable value
    date_format = workbook.add_format({
	'num_format': 'mm/dd/yy h:mm:ss'})

    # Sort our original input by count and date to assist with
	# creating charts.
    sorted_count = sort_by_count(data)
    sorted_date = sort_by_date(data)

    # Use list slicing to obtain the most and least frequently
    # used UA apps and the most recently used UA apps
    topten = sorted_count[-10:]
    leastten = sorted_count[:10]
    lastten = sorted_date[:10]

    # For the most recently used UA apps, convert the FILETIME
	# value to datetime format
    for element in lastten:
        element[1] = file_time(element[1])

    # Create a table for each of the three categories, specifying
	# the data, column headers, and formats for specific columns
    dashboard.add_table('A100:B110',
	{'data': topten, 'columns': [{'header': 'App'},
	{'header': 'Count'}]})
    dashboard.add_table('D100:E110',
	{'data': leastten, 'columns': [{'header': 'App'},
	{'header': 'Count'}]})
    dashboard.add_table('G100:H110',
	{'data': lastten, 'columns': [{'header': 'App'},
	{'header': 'Date (UTC)', 'format': date_format}]})

    # Create the most used UA apps chart
    top_chart = workbook.add_chart({'type': 'pie'})
    top_chart.set_title({'name': 'Top Ten Apps'})
    # Set the relative size to fit the labels and pie chart within
	# chart area
    top_chart.set_size({'x_scale': 1, 'y_scale': 2})

    # Add the data as a series by specifying the categories and
	# values
    top_chart.add_series(
	{'categories': '=Dashboard!$A$101:$A$110',
	'values': '=Dashboard!$B$101:$B$110',
	'data_labels': {'percentage': True}})
    # Add the chart to the 'Dashboard' worksheet
    dashboard.insert_chart('A4', top_chart)

    # Create the least used UA apps chart
    least_chart = workbook.add_chart({'type': 'pie'})
    least_chart.set_title({'name': 'Least Used Apps'})
    least_chart.set_size({'x_scale': 1, 'y_scale': 2})

    least_chart.add_series(
	{'categories': '=Dashboard!$D$101:$D$110',
	'values': '=Dashboard!$E$101:$E$110',
	'data_labels': {'percentage': True}})
    dashboard.insert_chart('J4', least_chart)

    # Create the most recently used UA apps chart
    last_chart = workbook.add_chart({'type': 'column'})
    last_chart.set_title({'name': 'Last Used Apps'})
    last_chart.set_size({'x_scale': 1.5, 'y_scale': 1})

    last_chart.add_series(
	{'categories': '=Dashboard!$G$101:$G$110',
	'values': '=Dashboard!$H$101:$H$110'})
    dashboard.insert_chart('D35', last_chart)


def userassist_writer(workbook, data, headers, ua_format):
    """
    The userassist_writer function creates the 'UserAssist'
	worksheet and table
    :param workbook: the excel workbook object
    :param data: the list of lists containing parsed UA data
    :param headers: a list of column names for the spreadsheet
    :param ua_format: the format object for the title and subtitle
	row
    :return: Nothing
    """
    userassist = workbook.add_worksheet('UserAssist')
    userassist.merge_range('A1:H1', 'XYZ Corp', ua_format)
    userassist.merge_range('A2:H2', 'Case ####', ua_format)

    # The format to use to convert datetime object into a
	# human readable value
    date_format = workbook.add_format(
	{'num_format': 'mm/dd/yy h:mm:ss'})

    # Convert the FILETIME object to datetime and insert the 'ID'
    # value as the first element in the list
    for i, element in enumerate(data):
        element[4] = file_time(element[4])
        element.insert(0, i + 1)

    # Calculate how big the table should be. Add 3 to account for
	# the title and header rows.
    length = len(data) + 3

    # Create the table; depending on the type (WinXP v. Win7) add
	# additional headers
    userassist.add_table(('A3:H' + str(length)),
                         {'data': data,
                          'columns': [{'header': 'ID'},
                          {'header': 'Name'},
					      {'header': 'Path'},
                          {'header': 'Session ID'},
						  {'header': 'Count'},
                          {'header': 'Last Run Time (UTC)',
						  'format': date_format},
                          {'header': 'Focus Time (MS)'},
                          {'header': 'Focus Count'}]})


def file_time(ft):
    """
    The file_time function converts the FILETIME objects into
	datetime objects
    :param ft: the FILETIME object
    :return: the datetime object
    """
    if ft is not None and ft != 0:
		return datetime(1601, 1, 1) + timedelta(microseconds=ft / 10)
	else:
		return 0


def sort_by_count(data):
    """
    The sort_by_count function sorts the lists by their count
	element
    :param data: the list of lists containing parsed UA data
    :return: the sorted count list of lists
    """
    # Return only the zero and third indexed item (the name and
	# count values) in the list after it has been sorted by the
    # count
    return [x[0:5:3] for x in sorted(data, key=itemgetter(3))]


def sort_by_date(data):
    """
    The sort_by_date function sorts the lists by their datetime
	object
    :param data: the list of lists containing parsed UA data
    :return: the sorted date list of lists
    """
    # Supply the reverse option to sort by descending order
    return [x[0:6:4] for x in sorted(data, key=itemgetter(4),
	reverse=True)]
