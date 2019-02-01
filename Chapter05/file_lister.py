"""File metadata capture and reporting utility."""
import argparse
import csv
import datetime
import logging
import os
import sqlite3
import sys

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
__description__ = '''This script uses a database to ingest and
    report meta data information about active entries in
    directories.'''
logger = logging.getLogger(__name__)


def main(custodian, target, db):
    """
    The main function creates the database or table, logs
        execution status, and handles errors
    :param custodian: The name of the custodian
    :param target: tuple containing the mode 'input' or 'output'
        as the first elemnet and a file path as the second
    :param db: The filepath for the database
    :return: None
    """
    logger.info('Initiating SQLite database: ' + db)
    conn = init_db(db)
    logger.info('Initialization Successful')
    logger.info('Retrieving or adding custodian: ' + custodian)
    custodian_id = get_or_add_custodian(conn, custodian)
    while not custodian_id:
        custodian_id = get_or_add_custodian(conn, custodian)
    logger.info('Custodian Retrieved')
    if target[0] == 'input':
        logger.info('Ingesting base input directory: {}'.format(
            target[1]))
        ingest_directory(conn, target[1], custodian_id)
        conn.commit()
        logger.info('Ingest Complete')
    elif target[0] == 'output':
        logger.info('Preparing to write output: ' + target[1])
        write_output(conn, target[1], custodian)
    else:
        raise argparse.ArgumentError(
            'Could not interpret run time arguments')

    conn.close()
    logger.info('Script Completed')


def init_db(db_path):
    """
    The init_db function opens or creates the database
    :param db_path: The filepath for the database
    :return: conn, the sqlite3 database connection
    """
    if os.path.exists(db_path):
        logger.info('Found Existing Database')
        conn = sqlite3.connect(db_path)
    else:
        logger.info('Existing database not found. '
                    'Initializing new database')
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()

        sql = """CREATE TABLE Custodians (
                 cust_id INTEGER PRIMARY KEY, name TEXT);"""
        cur.execute(sql)
        cur.execute('PRAGMA foreign_keys = 1;')
        sql = """CREATE TABLE Files(id INTEGER PRIMARY KEY,
            custodian INTEGER NOT NULL, file_name TEXT,
            file_path TEXT, extension TEXT, file_size INTEGER,
            mtime TEXT, ctime TEXT, atime TEXT, mode TEXT,
            inode INTEGER, FOREIGN KEY (custodian)
            REFERENCES Custodians(cust_id));"""
        cur.execute(sql)
        conn.commit()
    return conn


def get_or_add_custodian(conn, custodian):
    """
    The get_or_add_custodian function checks the database for a
        custodian and returns the ID if present;
    Or otherwise creates the custodian
    :param conn: The sqlite3 database connection object
    :param custodian: The name of the custodian
    :return: The custodian ID or None
    """
    cust_id = get_custodian(conn, custodian)
    cur = conn.cursor()
    if cust_id:
        cust_id = cust_id[0]
    else:
        sql = """INSERT INTO Custodians (cust_id, name) VALUES
            (null, '{}') ;""".format(custodian)
        cur.execute(sql)
        conn.commit()
    return cust_id


def get_custodian(conn, custodian):
    """
    The get_custodian function checks the database for a
        custodian and  returns the ID if present
    :param conn: The sqlite3 database connection object
    :param custodian: The name of the custodian
    :return: The custodian ID
    """
    cur = conn.cursor()
    sql = "SELECT cust_id FROM Custodians "\
          "WHERE name='{}';".format(custodian)
    cur.execute(sql)
    data = cur.fetchone()
    return data


def ingest_directory(conn, target, custodian_id):
    """
    The ingest_directory function reads file metadata and stores
        it in the database
    :param conn: The sqlite3 database connection object
    :param target: The path for the root directory to
        recursively walk
    :param custodian_id: The custodian ID
    :return: None
    """
    cur = conn.cursor()
    count = 0
    for root, _, files in os.walk(target):
        for file_name in files:
            meta_data = dict()
            try:
                meta_data['file_name'] = file_name
                meta_data['file_path'] = os.path.join(root,
                                                      file_name)
                meta_data['extension'] = os.path.splitext(
                    file_name)[-1]

                file_stats = os.stat(meta_data['file_path'])
                meta_data['mode'] = str(oct(file_stats.st_mode))
                meta_data['inode'] = int(file_stats.st_ino)
                meta_data['file_size'] = int(file_stats.st_size)
                meta_data['atime'] = format_timestamp(
                    file_stats.st_atime)
                meta_data['mtime'] = format_timestamp(
                    file_stats.st_mtime)
                meta_data['ctime'] = format_timestamp(
                    file_stats.st_ctime)
            except Exception as e:
                logger.error(
                    'Error processing file: {} {}'.format(
                        meta_data.get('file_path', None),
                        e.__str__()))
            meta_data['custodian'] = custodian_id
            sql = 'INSERT INTO Files ("{}") VALUES ({})'.format(
                '","'.join(meta_data.keys()),
                ', '.join('?' for x in meta_data.values()))
            try:
                cur.execute(sql, tuple(meta_data.values()))
            except (sqlite3.OperationalError,
                    sqlite3.IntegrityError) as e:
                logger.error(
                    "Could not insert statement {}"
                    " with values: {}".format(
                        sql, meta_data.values()))
                logger.error("Error message: {}".format(e))
            count += 1
        conn.commit()
    conn.commit()
    logger.info('Stored meta data for {} files.'.format(count))


def format_timestamp(timestamp):
    """
    The format_timestamp function formats an integer to a string
        timestamp
    :param timestamp: An integer timestamp
    :return: ts_format, a formatted (YYYY-MM-DD HH:MM:SS) string
    """
    ts_datetime = datetime.datetime.fromtimestamp(timestamp)
    ts_format = ts_datetime.strftime('%Y-%m-%d %H:%M:%S')
    return ts_format


def write_output(conn, target, custodian):
    """
    The write_output function handles writing either the CSV or
        HTML reports
    :param conn: The sqlite3 database connection object
    :param target: The output filepath
    :param custodian: Name of the custodian
    :return: None
    """
    custodian_id = get_custodian(conn, custodian)
    cur = conn.cursor()
    if custodian_id:
        custodian_id = custodian_id[0]
        sql = "SELECT COUNT(id) FROM Files "\
              "where custodian = {}".format(
                  custodian_id)
        cur.execute(sql)
        count = cur.fetchone()
    else:
        logger.error(
            'Could not find custodian in database. Please check '
            'the input of the custodian name and database path')

    if not count or not count[0] > 0:
        logger.error('Files not found for custodian')
    elif target.endswith('.csv'):
        write_csv(conn, target, custodian_id)
    elif target.endswith('.html'):
        write_html(conn, target, custodian_id, custodian)
    elif not (target.endswith('.html')or target.endswith('.csv')):
        logger.error('Could not determine file type')
    else:
        logger.error('Unknown Error Occurred')


def write_csv(conn, target, custodian_id):
    """
    The write_csv function generates a CSV report from the
        Files table
    :param conn: The Sqlite3 database connection object
    :param target: The output filepath
    :param custodian_id: The custodian ID
    :return: None
    """
    cur = conn.cursor()
    sql = "SELECT * FROM Files where custodian = {}".format(
        custodian_id)
    cur.execute(sql)

    cols = [description[0] for description in cur.description]
    logger.info('Writing CSV report')
    with open(target, 'w') as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(cols)

        for entry in cur:
            csv_writer.writerow(entry)
        csv_file.flush()
    logger.info('CSV report completed: ' + target)


def write_html(conn, target, custodian_id, custodian_name):
    """
    The write_html function generates an HTML report from the
        Files table
    :param conn: The sqlite3 database connection object
    :param target: The output filepath
    :param custodian_id: The custodian ID
    :return: None
    """
    cur = conn.cursor()
    sql = "SELECT * FROM Files where custodian = {}".format(
        custodian_id)
    cur.execute(sql)

    cols = [description[0] for description in cur.description]
    table_header = '</th><th>'.join(cols)
    table_header = '<tr><th>' + table_header + '</th></tr>'

    logger.info('Writing HTML report')

    with open(target, 'w') as html_file:
        html_string = """<html><body>\n
            <link rel="stylesheet"
                href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/css/bootstrap.min.css">
            <h1>File Listing for Custodian ID: {}, {}</h1>\n
            <table class='table table-hover table-striped'>\n
            """.format(custodian_id, custodian_name)
        html_file.write(html_string)
        html_file.write(table_header)

        for entry in cur:
            row_data = "</td><td>".join(
                [str(x) for x in entry])
            html_string = "\n<tr><td>" + row_data + "</td></tr>"
            html_file.write(html_string)
            html_file.flush()
        html_string = "\n</table>\n</body></html>"
        html_file.write(html_string)
    logger.info('HTML Report completed: ' + target)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=__description__,
        epilog='Built by {}. Version {}'.format(
            ", ".join(__authors__), __date__),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        'CUSTODIAN', help='Name of custodian collection is of.')
    parser.add_argument(
        'DB_PATH', help='File path and name of database to '
                        'create or append metadat to.')
    parser.add_argument(
        '--input', help='Base directory to scan.')
    parser.add_argument(
        '--output', help='Output file to write to. use `.csv` '
                         'extension for CSV and `.html` for HTML')
    parser.add_argument(
        '-l', help='File path and name of log file.')
    args = parser.parse_args()

    if args.input:
        arg_source = ('input', args.input)
    elif args.output:
        arg_source = ('output', args.output)
    else:
        raise argparse.ArgumentError(
            'Please specify input or output')

    if args.l:
        if not os.path.exists(args.l):
            os.makedirs(args.l)  # create log directory path
        log_path = os.path.join(args.l, 'file_lister.log')
    else:
        log_path = 'file_lister.log'

    logger.setLevel(logging.DEBUG)
    msg_fmt = logging.Formatter("%(asctime)-15s %(funcName)-20s"
                                "%(levelname)-8s %(message)s")
    strhndl = logging.StreamHandler(sys.stdout)
    strhndl.setFormatter(fmt=msg_fmt)
    fhndl = logging.FileHandler(log_path, mode='a')
    fhndl.setFormatter(fmt=msg_fmt)
    logger.addHandler(strhndl)
    logger.addHandler(fhndl)

    logger.info('Starting File Lister v.' + str(__date__))
    logger.debug('System ' + sys.platform)
    logger.debug('Version ' + sys.version)

    args_dict = {'custodian': args.CUSTODIAN,
        'target': arg_source, 'db': args.DB_PATH}

    main(**args_dict)
