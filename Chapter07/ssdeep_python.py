"""Example script that uses the ssdeep python bindings."""
import argparse
import logging
import os
import sys

import ssdeep

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
__description__ = '''Compare known file to another file or files
    in a directory using ssdeep.'''

# Argument handling constants
OUTPUT_OPTS = ['txt', 'json', 'csv']
logger = logging.getLogger(__file__)


def main(known_file, comparison, output_type):
    """
    The main function handles the main operations of the script
    :param known_file: path to known file
    :param comparison: path to look for similar files
    :param output_type: type of output to provide
    :return: None
    """

    # Check output formats
    if output_type not in OUTPUT_OPTS:
        logger.error(
            "Unsupported output format '{}' selected. Please "
            "use one of {}".format(
                output_type, ", ".join(OUTPUT_OPTS)))
        sys.exit(2)
    elif output_type == 'csv':
        # Special handling for CSV headers
        print('"similarity","known_file","known_hash",'
              '"comp_file","comp_hash"')

    # Check provided file paths
    known_file = os.path.abspath(known_file)
    comparison = os.path.abspath(comparison)

    # Generate ssdeep signature for known file
    if not os.path.exists(known_file):
        logger.error("Error - path {} not found".format(
            comparison))
        sys.exit(1)

    known_hash = ssdeep.hash_from_file(known_file)

    # Generate and test ssdeep signature for comparison file(s)
    if os.path.isdir(comparison):
        # Process files in folders
        for root, _, files in os.walk(comparison):
            for f in files:
                file_entry = os.path.join(root, f)
                comp_hash = ssdeep.hash_from_file(file_entry)
                comp_val = ssdeep.compare(known_hash, comp_hash)
                output(known_file, known_hash,
                       file_entry, comp_hash,
                       comp_val, output_type)

    elif os.path.isfile(comparison):
        # Process a single file
        comp_hash = ssdeep.hash_from_file(comparison)
        comp_val = ssdeep.compare(known_hash, comp_hash)
        output(known_file, known_hash, file_entry, comp_hash,
               comp_val, output_type)
    else:
        logger.error("Error - path {} not found".format(
            comparison))
        sys.exit(1)


def output(known_file, known_hash, comp_file, comp_hash, comp_val,
           output_type='txt'):
    """Write the output of the script in the specified format
    :param sigval (str): Calculated hash
    :param filename (str): name of the file processed
    :param output_type (str): Formatter to use for output
    """
    comp_val = str(comp_val)
    if output_type == 'txt':
        msg = "{similarity} - {known_file} {known_hash} | "
        msg += "{comp_file} {comp_hash}"
    elif output_type == 'json':
        msg = '{{"similarity": {similarity}, "known_file": '
        msg += '"{known_file}", "known_hash": "{known_hash}", '
        msg += '"comparison_file": "{comp_file}", '
        msg += '"comparison_hash": "{comp_hash}"}}'
    elif output_type == 'csv':
        msg = '"{similarity}","{known_file}","{known_hash}"'
        msg += '"{comp_file}","{comp_hash}"'
    else:
        raise NotImplementedError(
            "Unsupported output type: {}".format(output_type))

    print(msg.format(
        similarity=comp_val,
        known_file=known_file,
        known_hash=known_hash,
        comp_file=comp_file,
        comp_hash=comp_hash))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=__description__,
        epilog='Built by {}. Version {}'.format(
            ", ".join(__authors__), __date__),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('KNOWN',
        help='Path to known file to use to compare')
    parser.add_argument('COMPARISON',
        help='Path to file or directory to compare to known. '
             'Will recurse through all sub directories')
    parser.add_argument('-o', '--output-type',
        help='Format of output.', choices=OUTPUT_OPTS,
        default="txt")
    parser.add_argument('-l', help='specify log file path',
        default="./")

    args = parser.parse_args()

    if args.l:
        if not os.path.exists(args.l):
            os.makedirs(args.l)
        log_path = os.path.join(args.l, 'ssdeep_python.log')
    else:
        log_path = 'ssdeep_python.log'


    logger.setLevel(logging.DEBUG)
    msg_fmt = logging.Formatter("%(asctime)-15s %(funcName)-20s"
                                "%(levelname)-8s %(message)s")
    strhndl = logging.StreamHandler(sys.stderr)  # Set to stderr
    strhndl.setFormatter(fmt=msg_fmt)
    fhndl = logging.FileHandler(log_path, mode='a')
    fhndl.setFormatter(fmt=msg_fmt)
    logger.addHandler(strhndl)
    logger.addHandler(fhndl)

    logger.info('Starting SSDeep Python v. {}'.format(__date__))
    logger.debug('System ' + sys.platform)
    logger.debug('Version ' + sys.version.replace("\n", " "))

    logger.info('Script Starting')
    main(args.KNOWN, args.COMPARISON, args.output_type)
    logger.info('Script Completed')
