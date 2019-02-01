"""Third iteration of a simple XLSX writer."""

import xlsxwriter
from datetime import datetime

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

school_data = [['Computer Science', 235, 3.44,
				datetime(2015, 7, 23, 18, 0, 0)],
			   ['Chemistry', 201, 3.26,
			   datetime(2015, 7, 25, 9, 30, 0)],
			   ['Forensics', 99, 3.8,
			   datetime(2015, 7, 23, 9, 30, 0)],
			   ['Astronomy', 115, 3.21,
			   datetime(2015, 7, 19, 15, 30, 0)]]


def write_xlsx(data):
	"""
	The write_xlsx function creates an XLSX spreadsheet from a
	list of lists
	:param data: A list of lists to be written in the spreadsheet
	:return: Nothing
	"""
	workbook = xlsxwriter.Workbook('MyWorkbook.xlsx')
	main_sheet = workbook.add_worksheet('MySheet')

	date_format = workbook.add_format(
	{'num_format': 'mm/dd/yy hh:mm:ss AM/PM'})
	length = str(len(data) + 1)
	
	main_sheet.add_table(('A1:D' + length), 
	{'data': data,
	 'columns': [{'header': 'Department'}, {'header': 'Students'},
				 {'header': 'Cumulative GPA'},
				 {'header': 'Final Date',
				 'format': date_format}]})

	department_grades = workbook.add_chart({'type':'column'})
	department_grades.set_title(
	{'name':'Department and Grade distribution'})
	department_grades.add_series(
	{'categories':'=MySheet!$A$2:$A$5',
	'values':'=MySheet!$C$2:$C$5'})
	main_sheet.insert_chart('A8', department_grades)
	workbook.close()


write_xlsx(school_data)
