from __future__ import print_function
import os
import logging

import simplekml

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


def kml_writer(output_data, output_dir, output_name):
    """
    The kml_writer function writes JPEG and TIFF EXIF GPS data to
	a Google Earth KML file. This file can be opened
    in Google Earth and will use the GPS coordinates to create
	'pins' on the map of the taken photo's location.
    :param output_data: The embedded EXIF metadata to be written
    :param output_dir: The output directory to write the KML file.
    :param output_name: The name of the output KML file.
    :return:
    """
    msg = 'Writing ' + output_name + ' KML output.'
    print('[+]', msg)
    logging.info(msg)
    # Instantiate a Kml object and pass along the output filename
    kml = simplekml.Kml(name=output_name)
    for exif in output_data:
        if ('Latitude' in exif.keys() and
		'Latitude Reference' in exif.keys() and
		'Longitude Reference' in exif.keys() and
		'Longitude' in exif.keys()):

            if 'Original Date' in exif.keys():
                dt = exif['Original Date']
            else:
                dt = 'N/A'

            if exif['Latitude Reference'] == 'S':
                latitude = '-' + exif['Latitude']
            else:
                latitude = exif['Latitude']

            if exif['Longitude Reference'] == 'W':
                longitude = '-' + exif['Longitude']
            else:
                longitude = exif['Longitude']

            kml.newpoint(name=exif['Name'],
			description='Originally Created: ' + dt,
			coords=[(longitude, latitude)])
        else:
            pass
    kml.save(os.path.join(output_dir, output_name))