import os
from time import gmtime, strftime
from helper import utility
from mutagen import mp3, id3

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
    The main function confirms the file type and sends it to
    be processed.
    :param filename: name of the file potentially containing exif
    metadata.
    :return: A dictionary from get_tags, containing the embedded
    EXIF metadata.
    """

    # MP3 signatures
    signatures = ['494433']
    if utility.check_header(filename, signatures, 3) is True:
        return get_tags(filename)
    else:
        raise TypeError


def get_tags(filename):
    """
    The get_tags function extracts the ID3 metadata from the data
    object.
    :param filename: the path and name to the data object.
    :return: tags and headers, tags is a dictionary containing ID3
    metadata and headers are the order of keys for the CSV output.
    """

    # Set up CSV headers
    header = ['Path', 'Name', 'Size', 'Filesystem CTime',
    'Filesystem MTime', 'Title', 'Subtitle', 'Artist', 'Album',
    'Album/Artist', 'Length (Sec)', 'Year', 'Category',
    'Track Number', 'Comments', 'Publisher', 'Bitrate',
    'Sample Rate', 'Encoding', 'Channels', 'Audio Layer']
    tags = {}
    tags['Path'] = filename
    tags['Name'] = os.path.basename(filename)
    tags['Size'] = utility.convert_size(
    os.path.getsize(filename))
    tags['Filesystem CTime'] = strftime('%m/%d/%Y %H:%M:%S',
    gmtime(os.path.getctime(filename)))
    tags['Filesystem MTime'] = strftime('%m/%d/%Y %H:%M:%S',
    gmtime(os.path.getmtime(filename)))

    # MP3 Specific metadata
    audio = mp3.MP3(filename)
    if 'TENC' in audio.keys():
        tags['Encoding'] = audio['TENC'][0]
    tags['Bitrate'] = audio.info.bitrate
    tags['Channels'] = audio.info.channels
    tags['Audio Layer'] = audio.info.layer
    tags['Length (Sec)'] = audio.info.length
    tags['Sample Rate'] = audio.info.sample_rate

    # ID3 embedded metadata tags
    id = id3.ID3(filename)
    if 'TPE1' in id.keys():
        tags['Artist'] = id['TPE1'][0]
    if 'TRCK' in id.keys():
        tags['Track Number'] = id['TRCK'][0]
    if 'TIT3' in id.keys():
        tags['Subtitle'] = id['TIT3'][0]
    if 'COMM::eng' in id.keys():
        tags['Comments'] = id['COMM::eng'][0]
    if 'TDRC' in id.keys():
        tags['Year'] = id['TDRC'][0]
    if 'TALB' in id.keys():
        tags['Album'] = id['TALB'][0]
    if 'TIT2' in id.keys():
        tags['Title'] = id['TIT2'][0]
    if 'TCON' in id.keys():
        tags['Category'] = id['TCON'][0]
    if 'TPE2' in id.keys():
        tags['Album/Artist'] = id['TPE2'][0]
    if 'TPUB' in id.keys():
        tags['Publisher'] = id['TPUB'][0]

    return tags, header
