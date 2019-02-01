"""Index and summarize PST files"""
import os
import sys
import argparse
import logging
from collections import Counter

import jinja2
import pypff
import unicodecsv as csv

"""
LGPLv3 License

Copyright (c) 2018 Chapin Bryce, Preston Miller

Please share comments and questions at:
  https://github.com/PythonForensics/Learning-Python-for-Forensics
  or email pyforcookbook@gmail.com

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this program; if not, write to the
    Free Software Foundation, Inc.,
    51 Franklin Street,
    Fifth Floor,
    Boston, MA  02110-1301, USA.
"""

__authors__ = ["Chapin Bryce", "Preston Miller"]
__date__ = 20181027
__description__ = '''This scripts handles processing and
    output of PST Email Containers'''
logger = logging.getLogger(__name__)

output_directory = ""
date_dict = {x:0 for x in range(1, 25)}
date_list = [date_dict.copy() for x in range(7)]


def main(pst_file, report_name):
    """
    The main function opens a PST and calls functions to parse
        and report data from the PST
    :param pst_file: A string representing the path to the PST
        file to analyze
    :param report_name: Name of the report title
        (if supplied by the user)
    :return: None
    """
    logger.debug("Opening PST for processing...")
    pst_name = os.path.split(pst_file)[1]
    opst = pypff.open(pst_file)
    root = opst.get_root_folder()

    logger.debug("Starting traverse of PST structure...")
    folder_traverse(root)

    logger.debug("Generating Reports...")
    top_word_list = word_stats()
    top_sender_list = sender_report()
    date_report()

    html_report(report_name, pst_name, top_word_list,
        top_sender_list)


def make_path(file_name):
    """
    The make_path function provides an absolute path between the
    output_directory and a file
    :param file_name: A string representing a file name
    :return: A string representing the path to a specified file
    """
    return os.path.abspath(os.path.join(output_directory,
        file_name))


def folder_traverse(base):
    """
    The folder_traverse function walks through the base of the
        folder and scans for sub-folders and messages
    :param base: Base folder to scan for new items within
        the folder.
    :return: None
    """
    for folder in base.sub_folders:
        if folder.number_of_sub_folders:
            folder_traverse(folder) # Call new folder to traverse
        check_for_msgs(folder)


def check_for_msgs(folder):
    """
    The check_for_msgs function reads folder messages if
        present and passes them to the report function
    :param folder: pypff.Folder object
    :return: None
    """
    logger.debug("Processing Folder: " + folder.name)
    message_list = []
    for message in folder.sub_messages:
        message_dict = process_msg(message)
        message_list.append(message_dict)
    folder_report(message_list, folder.name)


def process_msg(message):
    """
    The process_msg function processes multi-field messages
        to simplify collection of information
    :param message: pypff.Message object
    :return: A dictionary with message fields (values) and
        their data (keys)
    """
    return {
        "subject": message.subject,
        "sender": message.sender_name,
        "header": message.transport_headers,
        "body": message.plain_text_body,
        "creation_time": message.creation_time,
        "submit_time": message.client_submit_time,
        "delivery_time": message.delivery_time,
        "attachment_count": message.number_of_attachments,
    }


def folder_report(message_list, folder_name):
    """
    The folder_report function generates a report per PST folder
    :param message_list: A list of messages discovered
        during scans
    :folder_name: The name of an Outlook folder within a PST
    :return: None
    """
    if not len(message_list):
        logger.warning("Empty message not processed")
        return

    # CSV Report
    fout_path = make_path("folder_report_" + folder_name + ".csv")
    fout = open(fout_path, 'wb')
    header = ['creation_time', 'submit_time', 'delivery_time',
              'sender', 'subject', 'attachment_count']
    csv_fout = csv.DictWriter(fout, fieldnames=header,
        extrasaction='ignore')
    csv_fout.writeheader()
    csv_fout.writerows(message_list)
    fout.close()

    # HTML Report Prep
    global date_list  # Allow access to edit global variable
    body_out = open(make_path("message_body.txt"), 'a')
    senders_out = open(make_path("senders_names.txt"), 'a')
    for m in message_list:
        if m['body']:
            body_out.write(m['body'] + "\n\n")
        if m['sender']:
            senders_out.write(m['sender'] + '\n')

        # Creation Time
        c_time = m['creation_time']
        if c_time is not None:
            day_of_week = c_time.weekday()
            hour_of_day = c_time.hour + 1
            date_list[day_of_week][hour_of_day] += 1
        # Submit Time
        s_time = m['submit_time']
        if s_time is not None:
            day_of_week = s_time.weekday()
            hour_of_day = s_time.hour + 1
            date_list[day_of_week][hour_of_day] += 1
        # Delivery Time
        d_time = m['delivery_time']
        if d_time is not None:
            day_of_week = d_time.weekday()
            hour_of_day = d_time.hour + 1
            date_list[day_of_week][hour_of_day] += 1
    body_out.close()
    senders_out.close()


def word_stats(raw_file="message_body.txt"):
    """
    The word_stats function reads and counts words from a file
    :param raw_file: The path to a file to read
    :return: A list of word frequency counts
    """
    word_list = Counter()
    for line in open(make_path(raw_file), 'r').readlines():
        for word in line.split():
            # Prevent too many false positives/common words
            if word.isalnum() and len(word) > 4:
                word_list[word] += 1
    return word_report(word_list)


def word_report(word_list):
    """
    The word_report function counts a list of words and returns
        results in a CSV format
    :param word_list: A list of words to iterate through
    :return: None or html_report_list, a list of word
        frequency counts
    """
    if not word_list:
        logger.debug('Message body statistics not available')
        return []

    fout = open(make_path("frequent_words.csv"), 'wb')
    fout.write("Count,Word\n")
    for e in word_list.most_common():
        if len(e) > 1:
            fout.write(str(e[1]) + "," + str(e[0]) + "\n")
    fout.close()

    html_report_list = []
    for e in word_list.most_common(10):
        html_report_list.append(
            {"word": str(e[0]), "count": str(e[1])})

    return html_report_list


def sender_report(raw_file="senders_names.txt"):
    """
    The sender_report function reports the most frequent_senders
    :param raw_file: The file to read raw information
    :return: html_report_list, a list of the most
        frequent senders
    """
    sender_list = Counter(
        open(make_path(raw_file), 'r').readlines())

    fout = open(make_path("frequent_senders.csv"), 'wb')
    fout.write("Count,Sender\n")
    for e in sender_list.most_common():
        if len(e) > 1:
            fout.write(str(e[1]) + "," + str(e[0]))
    fout.close()

    html_report_list = []
    for e in sender_list.most_common(5):
        html_report_list.append(
            {"label": str(e[0]), "count": str(e[1])})

    return html_report_list


def date_report():
    """
    The date_report function writes date information in a
        TSV report. No input args as the filename
    is static within the HTML dashboard
    :return: None
    """
    csv_out = open(make_path("heatmap.tsv"), 'w')
    csv_out.write("day\thour\tvalue\n")
    for date, hours_list in enumerate(date_list):
        for hour, count in hours_list.items():
            to_write = "{}\t{}\t{}\n".format(date+1, hour, count)
            csv_out.write(to_write)
        csv_out.flush()
    csv_out.close()


def html_report(report_title, pst_name, top_words, top_senders):
    """
    The html_report function generates the HTML report from a
        Jinja2 Template
    :param report_title: A string representing the title of
        the report
    :param pst_name: A string representing the file name of
        the PST
    :param top_words: A list of the top 10 words
    :param top_senders: A list of the top 10 senders
    :return: None
    """
    open_template = open("stats_template.html", 'r').read()
    html_template = jinja2.Template(open_template)

    context = {"report_title": report_title, "pst_name": pst_name,
               "word_frequency": top_words,
               "percentage_by_sender": top_senders}
    new_html = html_template.render(context)

    html_report_file = open(make_path("pst_report.html"), 'w')
    html_report_file.write(new_html)
    html_report_file.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=__description__,
        epilog='Built by {}. Version {}'.format(
            ", ".join(__authors__), __date__),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('PST_FILE',
        help="PST File Format from Microsoft Outlook")
    parser.add_argument('OUTPUT_DIR',
        help="Directory of output for temporary and report files.")
    parser.add_argument('--title', default="PST Report",
        help='Title of the HTML Report.')
    parser.add_argument('-l',
        help='File path of log file.')
    args = parser.parse_args()

    output_directory = os.path.abspath(args.OUTPUT_DIR)

    if not os.path.exists(output_directory):
        os.makedirs(output_directory)

    if args.l:
        if not os.path.exists(args.l):
            os.makedirs(args.l)  # create log directory path
        log_path = os.path.join(args.l, 'pst_indexer.log')
    else:
        log_path = 'pst_indexer.log'

    logger.setLevel(logging.DEBUG)
    msg_fmt = logging.Formatter("%(asctime)-15s %(funcName)-20s"
                                "%(levelname)-8s %(message)s")
    strhndl = logging.StreamHandler(sys.stderr)  # Set to stderr
    strhndl.setFormatter(fmt=msg_fmt)
    fhndl = logging.FileHandler(log_path, mode='a')
    fhndl.setFormatter(fmt=msg_fmt)
    logger.addHandler(strhndl)
    logger.addHandler(fhndl)

    logger.info('Starting PST Indexer v. {}'.format(__date__))
    logger.debug('System ' + sys.platform)
    logger.debug('Version ' + sys.version.replace("\n", " "))

    logger.info('Starting Script')
    main(args.PST_FILE, args.title)
    logger.info('Script Complete')
