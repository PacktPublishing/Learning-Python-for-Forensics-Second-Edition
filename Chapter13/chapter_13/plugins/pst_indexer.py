import pypff

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


def main(pst_file):
    """
    The main function opens a PST and calls functions to parse
    and report data from the PST
    :param pst_file: A string representing the path to the PST
    file to analyze
    :return: None
    """
    opst = pypff.open(pst_file)
    root = opst.get_root_folder()

    message_data = folder_traverse(root, [],
    **{'pst_name': pst_file, 'folder_name': 'root'})

    header = ['pst_name', 'folder_name', 'creation_time',
    'submit_time', 'delivery_time', 'sender', 'subject', 'attachment_count']

    return message_data, header


def folder_traverse(base, message_data, pst_name, folder_name):
    """
    The folder_traverse function walks through the base of the
    folder and scans for sub-folders and messages
    :param base: Base folder to scan for new items within the
    folder
    :param message_data: A list of data for output
    :param pst_name: A string representing the name of the PST
    file
    :param folder_name: A string representing the name of the
    folder
    :return: None
    """
    for folder in base.sub_folders:
        if folder.number_of_sub_folders:
            message_data = folder_traverse(folder, message_data,
            pst_name, folder.name)
        message_data = check_for_messages(folder, message_data,
        pst_name, folder.name)
    return message_data


def check_for_messages(folder, message_data, pst_name, folder_name):
    """
    The check_for_messages function reads folder messages if
    present and passes them to the report function
    :param folder: pypff.Folder object
    :param message_data: list to pass and extend with message info
    :param pst_name: A string representing the name of the PST
    file
    :param folder_name: A string representing the name of the
    folder
    :return: Dictionary of results by folder
    """
    for message in folder.sub_messages:
        message_dict = process_message(message)
        message_dict['pst_name'] = pst_name
        message_dict['folder_name'] = folder_name
        message_data.append(message_dict)
    return message_data


def process_message(message):
    """
    The process_message function processes multi-field messages to
    simplify collection of information
    :param message: The pypff.Message object
    :return: A dictionary with message fields (values) and their
    data (keys)
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
