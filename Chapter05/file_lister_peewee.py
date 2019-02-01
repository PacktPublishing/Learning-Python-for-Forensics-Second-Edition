"""File metadata capture and reporting utility."""
import argparse
import datetime
from io import open
import logging
import os
import sys
import unicodecsv as csv
import peewee
import jinja2

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
database_proxy = peewee.Proxy()

class BaseModel(peewee.Model):
    class Meta:
        database = database_proxy

class Custodians(BaseModel):
    name = peewee.TextField(unique=True)

class Files(BaseModel):
    id = peewee.PrimaryKeyField(unique=True, primary_key=True)
    custodian = peewee.ForeignKeyField(Custodians)
    file_name = peewee.TextField()
    file_path = peewee.TextField()
    extension = peewee.TextField()
    file_size = peewee.IntegerField()
    atime = peewee.DateTimeField()
    mtime = peewee.DateTimeField()
    ctime = peewee.DateTimeField()
    mode = peewee.TextField()
    inode = peewee.IntegerField()


def get_template():
    """
    The get_template function returns a basic template for our
        HTML report
    :return: Jinja2 Template
    """
    html_string = """
        <html>\n<head>\n<link rel="stylesheet"
        href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/css/bootstrap.min.css">
        </head>\n<body>\n<h1>
            File Listing for Custodian {{ custodian.id }},
            {{ custodian.name }}</h1>\n
        <table class="table table-hover table-striped">\n
        <tr>\n
        {% for header in table_headers %}
            <th>{{ header }}</th>
        {% endfor %}
        </tr>\n
        {% for entry in file_listing %}
            <tr>
                <td>{{ entry.id }}</td>
                <td>{{ entry.custodian.name }}</td>
                <td>{{ entry.file_name }}</td></td>
                <td>{{ entry.file_path }}</td>
                <td>{{ entry.extension }}</td>
                <td>{{ entry.file_size }}</td>
                <td>{{ entry.atime }}</td>
                <td>{{ entry.mtime }}</td>
                <td>{{ entry.ctime }}</td>
                <td>{{ entry.mode }}</td>
                <td>{{ entry.inode }}</td>
            </tr>\n
        {% endfor %}
        </table>\n</body>\n</html>"""
    return jinja2.Template(html_string)


def main(custodian, target, db):
    """
    The main function creates the database or table, logs
        execution status, and handles errors
    :param custodian: The name of the custodian
    :param target: tuple containing the mode 'input' or 'output'
        as the first element and its arguments as the second
    :param db: The file path for the database
    :return: None
    """
    logger.info('Initializing Database')
    init_db(db)
    logger.info('Initialization Successful')
    logger.info('Retrieving or adding custodian: ' + custodian)
    custodian_model = get_or_add_custodian(custodian)
    if target[0] == 'input':
        logger.info('Ingesting base input directory: {}'.format(
            target[1]))
        ingest_directory(target[1], custodian_model)
        logger.info('Ingesting Complete')
    elif target[0] == 'output':
        logger.info(
            'Preparing to write output for custodian: {}'.format(
                custodian))
        write_output(target[1], custodian_model)
        logger.info('Output Complete')
    else:
        logger.error('Could not interpret run time arguments')

    logger.info('Script Complete')


def init_db(db):
    """
    The init_db function opens or creates the database
    :param db_path: The file path for the database
    :return: conn, the sqlite3 database connection
    """
    database = peewee.SqliteDatabase(db)
    database_proxy.initialize(database)
    table_list = [Custodians, Files]  # Update with any new tables
    database.create_tables(table_list, safe=True)


def get_or_add_custodian(custodian):
    """
    The get_or_add_custodian function gets the custodian by name
         or adds it to the table
    :param custodian: The name of the custodian
    :return: custodian_model, custodian peewee model instance
    """
    custodian_model, created = Custodians.get_or_create(
        name=custodian)
    if created:
        logger.info('Custodian added')
    else:
        logger.info('Custodian retrieved')

    return custodian_model


def ingest_directory(source, custodian_model):
    """
    The ingest_directory function reads file metadata and stores
        it in the database
    :param source: The path for the root directory to
        recursively walk
    :param custodian_model: Peewee model instance for the
        custodian
    :return: None
    """
    file_data = []
    for root, _, files in os.walk(source):
        for file_name in files:
            ddate = datetime.datetime.min
            meta_data = {
                'file_name': None, 'file_path': None,
                'extension': None, 'mode': -1, 'inode': -1,
                'file_size': -1, 'atime': ddate, 'mtime': ddate,
                'ctime': ddate, 'custodian': custodian_model.id}
            try:
                meta_data['file_name'] = os.path.join(file_name)
                meta_data['file_path'] = os.path.join(root,
                                                      file_name)
                meta_data['extension'] = os.path.splitext(
                    file_name)[-1]

                file_stats = os.stat(meta_data['file_path'])
                meta_data['mode'] = str(oct(file_stats.st_mode))
                meta_data['inode'] = str(file_stats.st_ino)
                meta_data['file_size'] = str(file_stats.st_size)
                meta_data['atime'] = format_timestamp(
                    file_stats.st_atime)
                meta_data['mtime'] = format_timestamp(
                    file_stats.st_mtime)
                meta_data['ctime'] = format_timestamp(
                    file_stats.st_ctime)
            except Exception as e:
                logger.error(
                    'Error processing file: {} {}'.format(
                        meta_data['file_path'], e.__str__()))
            file_data.append(meta_data)

    for x in range(0, len(file_data), 50):
        task = Files.insert_many(file_data[x:x+50])
        task.execute()
    logger.info('Stored meta data for {} files.'.format(
        len(file_data)))


def format_timestamp(ts):
    """
    The format_timestamp function converts an integer into a
        datetime object
    :param ts: An integer timestamp
    :return: A datetime object
    """
    return datetime.datetime.fromtimestamp(ts)


def write_output(source, custodian_model):
    """
    The writeOutput function handles writing either the CSV or
        HTML reports
    :param source: The output file path
    :param custodian_model: Peewee model instance for the
        custodian
    :return: None
    """
    count = Files.select().where(
        Files.custodian == custodian_model.id).count()

    logger.info("{} files found for custodian.".format(count))

    if not count:
        logger.error('Files not found for custodian')
    elif source.endswith('.csv'):
        write_csv(source, custodian_model)
    elif source.endswith('.html'):
        write_html(source, custodian_model)
    elif not (source.endswith('.html') or \
            source.endswith('.csv')):
        logger.error('Could not determine file type')
    else:
        logger.error('Unknown Error Occurred')


def write_csv(source, custodian_model):
    """
    The write_csv function generates a CSV report from the Files
        table
    :param source: The output file path
    :param custodian_model: Peewee model instance for the
        custodian
    :return: None
    """
    query = Files.select().where(
        Files.custodian == custodian_model.id).dicts()
    logger.info('Writing CSV report')

    cols = [u'id', u'custodian', u'file_name', u'file_path',
            u'extension', u'file_size', u'ctime', u'mtime',
            u'atime', u'mode', u'inode']

    with open(source, 'wb') as csv_file:
        csv_writer = csv.DictWriter(csv_file, cols)
        csv_writer.writeheader()
        for counter, row in enumerate(query):
            csv_writer.writerow(row)
            if counter % 10000 == 0:
                logger.debug('{:,} lines written'.format(counter))
        logger.debug('{:,} lines written'.format(counter))

    logger.info('CSV Report completed: ' + source)


def write_html(source, custodian_model):
    """
    The write_html function generates an HTML report from the
        Files table
    :param source: The output file path
    :param custodian_model: Peewee model instance for the
        custodian
    :return: None
    """
    template = get_template()
    table_headers = [
        'Id', 'Custodian', 'File Name', 'File Path',
        'File Extension', 'File Size', 'Created Time',
        'Modified Time', 'Accessed Time', 'Mode', 'Inode']
    file_data = Files.select().where(
        Files.custodian == custodian_model.id)

    template_dict = {
        'custodian': custodian_model,
        'table_headers': table_headers,
        'file_listing': file_data}

    logger.info('Writing HTML report')

    with open(source, 'w') as html_file:
        html_file.write(template.render(**template_dict))

    logger.info('HTML Report completed: ' + source)

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
