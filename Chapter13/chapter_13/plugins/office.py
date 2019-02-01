import zipfile
import os
from time import gmtime, strftime
from helper import utility

from lxml import etree

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


def main(filename):

    """
    The main function confirms the file type and sends it
    to be processed.
    :param filename: name of the file potentially containing
    embedded metadata.
    :return: A dictionary from getTags, containing the embedded
    metadata.
    """

    # DOCX, XLSX, and PPTX signatures
    signatures = ['504b030414000600']
    if utility.check_header(filename, signatures, 8) is True:
        return get_tags(filename)
    else:
        raise TypeError


def get_tags(filename):
    """
    The get_tags function extracts the office metadata from the
    data object.
    :param filename: the path and name to the data object.
    :return: tags and headers, tags is a dictionary containing
    office metadata and headers are the order of keys for the CSV
    output.
    """

    # Set up CSV headers
    headers = ['Path', 'Name', 'Size', 'Filesystem CTime',
    'Filesystem MTime', 'Title', 'Author(s)','Create Date',
    'Modify Date', 'Last Modified By Date', 'Subject', 'Keywords',
    'Description', 'Category', 'Status', 'Revision',
    'Edit Time (Min)', 'Page Count', 'Word Count',
    'Character Count', 'Line Count',
    'Paragraph Count', 'Slide Count', 'Note Count',
    'Hidden Slide Count', 'Company', 'Hyperlink Base']

    # Create a ZipFile class from the input object
    # This allows us to read or write to the 'Zip archive'
    try:
        zf = zipfile.ZipFile(filename)
    except zipfile.BadZipfile:
        return {}, headers

    # These two XML files contain the embedded metadata of
    # interest
    try:
        core = etree.fromstring(zf.read('docProps/core.xml'))
        app = etree.fromstring(zf.read('docProps/app.xml'))
    except KeyError as e:
        assert Warning(e)
        return {}, headers

    tags = {}
    tags['Path'] = filename
    tags['Name'] = os.path.basename(filename)
    tags['Size'] = utility.convert_size(
    os.path.getsize(filename))
    tags['Filesystem CTime'] = strftime('%m/%d/%Y %H:%M:%S',
    gmtime(os.path.getctime(filename)))
    tags['Filesystem MTime'] = strftime('%m/%d/%Y %H:%M:%S',
    gmtime(os.path.getmtime(filename)))

    # Core Tags

    for child in core.iterchildren():

        if 'title' in child.tag:
            tags['Title'] = child.text
        if 'subject' in child.tag:
            tags['Subject'] = child.text
        if 'creator' in child.tag:
            tags['Author(s)'] = child.text
        if 'keywords' in child.tag:
            tags['Keywords'] = child.text
        if 'description' in child.tag:
            tags['Description'] = child.text
        if 'lastModifiedBy' in child.tag:
            tags['Last Modified By Date'] = child.text
        if 'created' in child.tag:
            tags['Create Date'] = child.text
        if 'modified' in child.tag:
            tags['Modify Date'] = child.text
        if 'category' in child.tag:
            tags['Category'] = child.text
        if 'contentStatus' in child.tag:
            tags['Status'] = child.text

        if (filename.endswith('.docx') or
        filename.endswith('.pptx')):
            if 'revision' in child.tag:
                tags['Revision'] = child.text

    # App Tags
    for child in app.iterchildren():

        if filename.endswith('.docx'):
            if 'TotalTime' in child.tag:
                tags['Edit Time (Min)'] = child.text
            if 'Pages' in child.tag:
                tags['Page Count'] = child.text
            if 'Words' in child.tag:
                tags['Word Count'] = child.text
            if 'Characters' in child.tag:
                tags['Character Count'] = child.text
            if 'Lines' in child.tag:
                tags['Line Count'] = child.text
            if 'Paragraphs' in child.tag:
                tags['Paragraph Count'] = child.text
            if 'Company' in child.tag:
                tags['Company'] = child.text
            if 'HyperlinkBase' in child.tag:
                tags['Hyperlink Base'] = child.text

        elif filename.endswith('.pptx'):
            if 'TotalTime' in child.tag:
                tags['Edit Time (Min)'] = child.text
            if 'Words' in child.tag:
                tags['Word Count'] = child.text
            if 'Paragraphs' in child.tag:
                tags['Paragraph Count'] = child.text
            if 'Slides' in child.tag:
                tags['Slide Count'] = child.text
            if 'Notes' in child.tag:
                tags['Note Count'] = child.text
            if 'HiddenSlides' in child.tag:
                tags['Hidden Slide Count'] = child.text
            if 'Company' in child.tag:
                tags['Company'] = child.text
            if 'HyperlinkBase' in child.tag:
                tags['Hyperlink Base'] = child.text
        else:
            if 'Company' in child.tag:
                tags['Company'] = child.text
            if 'HyperlinkBase' in child.tag:
                tags['Hyperlink Base'] = child.text

    return tags, headers
