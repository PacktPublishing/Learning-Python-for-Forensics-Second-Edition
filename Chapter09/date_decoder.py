"""Example usage of Tkinter to convert dates."""
import datetime
import logging
import sys
if sys.version_info[0] == 2:
    from Tkinter import *
    import ttk
elif sys.version_info[0] == 3:
    from tkinter import *
    import tkinter.ttk as ttk
from dateutil import parser as duparser


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
__description__ = '''This script uses a GUI to show date values
    interpreted by common timestamp formats'''
logger = logging.getLogger(__name__)


class DateDecoder(object):
    """
    The DateDecoder class handles the construction of the GUI
    and the processing of date & time values
    """
    def __init__(self):
        """
        The __init__ method initializes the root GUI window and
        variable used in the script
        """
        # Init root window
        self.root = Tk()
        self.root.geometry("500x180+40+40")
        self.root.config(background = '#ECECEC')
        self.root.title('Date Decoder')

        # Init time values
        self.processed_unix_seconds = None
        self.processed_windows_filetime_64 = None
        self.processed_chrome_time = None

        # Set Constant Epoch Offset
        self.epoch_1601 = 11644473600000000
        self.epoch_1970 = datetime.datetime(1970,1,1)

    def run(self):
        """
        The run method calls appropriate methods to build the
        GUI and set's the event listener loop.
        """
        logger.info('Launching GUI')
        self.build_input_frame()
        self.build_output_frame()
        self.root.mainloop()

    def build_input_frame(self):
        """
        The build_input_frame method builds the interface for
        the input frame
        """
        # Frame Init
        self.input_frame = ttk.Frame(self.root)
        self.input_frame.config(padding = (30,0))
        self.input_frame.pack()

        # Input Value
        ttk.Label(self.input_frame,
            text="Enter Time Value").grid(row=0, column=0)

        self.input_time = StringVar()
        ttk.Entry(self.input_frame, textvariable=self.input_time,
            width=25).grid(row=0, column=1, padx=5)

        # Radiobuttons
        self.time_type = StringVar()
        self.time_type.set('raw')

        ttk.Radiobutton(self.input_frame, text="Raw Value",
            variable=self.time_type, value="raw").grid(row=1,
                column=0, padx=5)

        ttk.Radiobutton(self.input_frame, text="Formatted Value",
            variable=self.time_type, value="formatted").grid(
                row=1, column=1, padx=5)

        # Button
        ttk.Button(self.input_frame, text="Run",
            command=self.convert).grid(
                row=2, columnspan=2, pady=5)

    def build_output_frame(self):
        """
        The build_output_frame method builds the interface for
        the output frame
        """
        # Output Frame Init
        self.output_frame = ttk.Frame(self.root)
        self.output_frame.config(height=300, width=500)
        self.output_frame.pack()

        # Output Area
        ## Label for area
        self.output_label = ttk.Label(self.output_frame,
            text="Conversion Results")
        self.output_label.config(font=("", 16))
        self.output_label.pack(fill=X)

        ## For Unix Seconds Timestamps
        self.unix_sec = ttk.Label(self.output_frame,
            text="Unix Seconds: N/A")
        self.unix_sec.pack(fill=X)

        ## For Windows FILETIME 64 Timestamps
        self.win_ft_64 = ttk.Label(self.output_frame,
            text="Windows FILETIME 64: N/A")
        self.win_ft_64.pack(fill=X)

        ## For Chrome Timestamps
        self.google_chrome = ttk.Label(self.output_frame,
            text="Google Chrome: N/A")
        self.google_chrome.pack(fill=X)

    def convert(self):
        """
        The convert method handles the event when the button is
        pushed. It calls to the converters and updates the
        labels with new output.
        """
        logger.info('Processing Timestamp: {}'.format(
            self.input_time.get()))
        logger.info('Input Time Format: {}'.format(
            self.time_type.get()))

        # Init values every instance
        self.processed_unix_seconds = 'N/A'
        self.processed_windows_filetime_64 = 'N/A'
        self.processed_chrome_time = 'N/A'

        # Use this to call converters
        self.convert_unix_seconds()
        self.convert_win_filetime_64()
        self.convert_chrome_time()

        # Update labels
        self.output()

    def convert_unix_seconds(self):
        """
        The convert_unix_seconds method handles the conversion of
        timestamps per the UNIX seconds format
        """
        if self.time_type.get() == 'raw':
            try:
                dt_val = datetime.datetime.fromtimestamp(
                    float(self.input_time.get())).strftime(
                        '%Y-%m-%d %H:%M:%S')
                self.processed_unix_seconds = dt_val
            except Exception as e:
                logger.error(str(type(e)) + "," + str(e))
                self.processed_unix_seconds = str(
                    type(e).__name__)

        elif self.time_type.get() == 'formatted':
            try:
                converted_time = duparser.parse(
                    self.input_time.get())
                self.processed_unix_seconds = str(
                        (converted_time - self.epoch_1970
                    ).total_seconds())
            except Exception as e:
                logger.error(str(type(e)) + "," + str(e))
                self.processed_unix_seconds = str(
                    type(e).__name__)

    def convert_win_filetime_64(self):
        """
        The convert_win_filetime_64 method handles the
        conversion of timestamps per the Windows FILETIME format
        """
        if self.time_type.get() == 'raw':
            try:
                base10_microseconds = int(
                    self.input_time.get(), 16) / 10
                datetime_obj = datetime.datetime(1601,1,1) + \
                    datetime.timedelta(
                        microseconds=base10_microseconds)
                dt_val = datetime_obj.strftime(
                    '%Y-%m-%d %H:%M:%S.%f')
                self.processed_windows_filetime_64 = dt_val
            except Exception as e:
                logger.error(str(type(e)) + "," + str(e))
                self.processed_windows_filetime_64 = str(
                    type(e).__name__)

        elif self.time_type.get() == 'formatted':
            try:
                converted_time = duparser.parse(
                    self.input_time.get())
                minus_epoch = converted_time - \
                    datetime.datetime(1601,1,1)
                calculated_time = minus_epoch.microseconds + \
                    (minus_epoch.seconds * 1000000) + \
                    (minus_epoch.days * 86400000000)
                self.processed_windows_filetime_64 = str(
                    hex(int(calculated_time)*10))
            except Exception as e:
                logger.error(str(type(e)) + "," + str(e))
                self.processed_windows_filetime_64 = str(
                    type(e).__name__)

    def convert_chrome_time(self):
        """
        The convert_chrome_time method handles the
        conversion of timestamps per the Google Chrome
        timestamp format
        """
        # Run Conversion
        if self.time_type.get() == 'raw':
            try:
                dt_val = datetime.datetime.fromtimestamp(
                    (float(self.input_time.get()
                        )-self.epoch_1601)/1000000)
                self.processed_chrome_time = dt_val.strftime(
                    '%Y-%m-%d %H:%M:%S.%f')
            except Exception as e:
                logger.error(str(type(e)) + "," + str(e))
                self.processed_chrome_time = str(type(e).__name__)

        elif self.time_type.get() == 'formatted':
            try:
                converted_time = duparser.parse(
                    self.input_time.get())
                chrome_time = (converted_time - self.epoch_1970
                    ).total_seconds()*1000000 + self.epoch_1601
                self.processed_chrome_time = str(int(chrome_time))
            except Exception as e:
                logger.error(str(type(e)) + "," + str(e))
                self.processed_chrome_time = str(type(e).__name__)

    def output(self):
        """
        The output method updates the output frame with the
        latest value.
        """
        if isinstance(self.processed_unix_seconds, str):
            self.unix_sec['text'] = "Unix Seconds: " + \
                self.processed_unix_seconds

        if isinstance(self.processed_windows_filetime_64, str):
            self.win_ft_64['text'] = "Windows FILETIME 64: " + \
                self.processed_windows_filetime_64

        if isinstance(self.processed_chrome_time, str):
            self.google_chrome['text'] = "Google Chrome: " + \
                self.processed_chrome_time


if __name__ == '__main__':
    """
    This statement is used to initialize the GUI. No
    arguments needed as it is a graphic interface
    """
    # Initialize Logging
    log_path = 'date_decoder.log'

    logger.setLevel(logging.DEBUG)
    msg_fmt = logging.Formatter("%(asctime)-15s %(funcName)-20s"
                                "%(levelname)-8s %(message)s")
    fhndl = logging.FileHandler(log_path, mode='a')
    fhndl.setFormatter(fmt=msg_fmt)
    logger.addHandler(fhndl)

    logger.info('Starting Date Decoder v. {}'.format(__date__))
    logger.debug('System ' + sys.platform)
    logger.debug('Version ' + sys.version.replace("\n", " "))

    # Create Instance and run the GUI
    dd = DateDecoder()
    dd.run()
