"""Spamsum hash generator."""
import argparse
import logging
import json
import os
import sys

"""
Copyright (C) 2002 Andrew Tridgell <tridge@samba.org>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

CHANGELOG:
Implemented in Python as shown below by Chapin Bryce &
Preston Miller
"""

__authors__ = ["Chapin Bryce", "Preston Miller"]
__date__ = 20181027
__description__ = '''Generate file signatures using
    the spamsum algorithm.'''

# Base64 Alphabet
ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
ALPHABET += 'abcdefghijklmnopqrstuvwxyz0123456789+/'

# Constants for use with signature calculation
CONTEXT_WINDOW = 7
FNV_PRIME = 0x01000193
HASH_INIT = 0x28021967
SIGNATURE_LEN = 64

# Argument handling constants
OUTPUT_OPTS = ['txt', 'json', 'csv']
logger = logging.getLogger(__file__)


def main(file_path, output_type):
    """
    The main function handles the main operations of the script
    :param file_path: path to generate signatures for
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

    # Check provided file path
    file_path = os.path.abspath(file_path)
    if os.path.isdir(file_path):
        # Process files in folders
        for root, _, files in os.walk(file_path):
            for f in files:
                file_entry = os.path.join(root, f)
                sigval = fuzz_file(file_entry)
                output(sigval, file_entry, output_type)
    elif os.path.isfile(file_path):
        # Process a single file
        sigval = fuzz_file(file_path)
        output(sigval, file_path, output_type)
    else:
        # Handle an error
        logger.error("Error - path {} not found".format(
            file_path))
        sys.exit(1)


def fuzz_file(file_path):
    """
    The fuzz_file function creates a fuzzy hash of a file
    :param file_path (str): file to read.
    :return (str): spamsum hash
    """

    # Define our rolling hash function
    def update_rolling_hash(nb, rh):
        """
        Update the rolling hash value with the new byte
        :param nb (int): new_byte as read from file
        :param rh (dict): rolling hash tracking dictionary
        :return: computed hash value to compare to reset_point
        """
        # Calculate R2
        rh['r2'] -= rh['r1']
        rh['r2'] += (CONTEXT_WINDOW * nb)

        # Calculate R1
        rh['r1'] += nb
        rh['r1'] -= rh['rw'][rh['rn'] % CONTEXT_WINDOW]

        # Update RW and RN
        rh['rw'][rh['rn'] % CONTEXT_WINDOW] = nb
        rh['rn'] += 1

        # Calculate R3
        rh['r3'] = (rh['r3'] << 5) & 0xFFFFFFFF
        rh['r3'] = rh['r3'] ^ nb

        # Return the sum of R1 + R2 + R3
        return rh['r1'] + rh['r2'] + rh['r3']

    # Open file and get size for reset point calculation
    fsize = os.stat(file_path).st_size
    if fsize == 0:
        logger.warning("File is 0-bytes. Skipping...")
        return ""
    open_file = open(file_path, 'rb')

    # Calculate a reset point
    reset_point = 3
    while reset_point * 64 < fsize:
        reset_point *= 2

    # Setup our while loop for signature generation
    complete_file = bytearray(open_file.read())
    done = False
    while not done:
        # Initialize our hashes and signature variables
        rolling_hash = {
            'r1': 0,
            'r2': 0,
            'r3': 0,
            'rn': 0,
            'rw': [0 for _ in range(CONTEXT_WINDOW)]
        }
        trad_hash1 = HASH_INIT
        trad_hash2 = HASH_INIT
        sig1 = ""
        sig2 = ""

        # Start iteration over the bytearray of the file
        for new_byte in complete_file:
            # Calculate our rolling hash
            rh = update_rolling_hash(new_byte, rolling_hash)

            # Update our traditional hash using FNV
            trad_hash1 = (trad_hash1 * FNV_PRIME) ^ new_byte
            trad_hash2 = (trad_hash2 * FNV_PRIME) ^ new_byte

            # Check if our rolling hash reaches a reset point
            # If so, update sig and reset trad_hash
            if (rh % reset_point == reset_point - 1
                    and len(sig1) < SIGNATURE_LEN - 1):
                sig1 += ALPHABET[trad_hash1 % 64]
                trad_hash1 = HASH_INIT
            if (rh % (reset_point * 2) == (reset_point * 2) - 1
                    and len(sig2) < (SIGNATURE_LEN / 2) - 1):
                sig2 += ALPHABET[trad_hash2 % 64]
                trad_hash2 = HASH_INIT

        # If sig1 is too short, change block size and recalculate
        if len(sig1) < SIGNATURE_LEN / 2 and reset_point > 3:
            reset_point = reset_point // 2
            logger.debug("Shortening block size to {}".format(
                reset_point))
        else:
            done = True

        # Add any values from the tail to our hash
        if rh != 0:
            sig1 += ALPHABET[trad_hash1 % 64]
            sig2 += ALPHABET[trad_hash2 % 64]

    # Close the file and return our new signature
    open_file.close()
    return "{}:{}:{}".format(reset_point, sig1, sig2)


def output(sigval, filename, output_type='txt'):
    """Write the output of the script in the specified format
    :param sigval (str): Calculated hash
    :param filename (str): name of the file processed
    :param output_type (str): Formatter to use for output
    """
    if output_type == 'txt':
        print("{} {}".format(sigval, filename))
    elif output_type == 'json':
        print(json.dumps({"sig": sigval, "file": filename}))
    elif output_type == 'csv':
        print("{},\"{}\"".format(sigval, filename))
    else:
        raise NotImplementedError(
            "Unsupported output type: {}".format(output_type))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=__description__,
        epilog='Built by {}. Version {}'.format(
            ", ".join(__authors__), __date__),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('PATH',
        help='Path to file or folder to generate hashes for. '
             'Will run recursively.')
    parser.add_argument('-o', '--output-type',
        help='Format of output.', choices=OUTPUT_OPTS,
        default="txt")
    parser.add_argument('-l', help='specify log file path',
        default="./")

    args = parser.parse_args()

    if args.l:
        if not os.path.exists(args.l):
            os.makedirs(args.l)  # create log directory path
        log_path = os.path.join(args.l, 'fuzzy_hasher.log')
    else:
        log_path = 'fuzzy_hasher.log'

    logger.setLevel(logging.DEBUG)
    msg_fmt = logging.Formatter("%(asctime)-15s %(funcName)-20s"
                                "%(levelname)-8s %(message)s")
    strhndl = logging.StreamHandler(sys.stderr)  # Set to stderr
    strhndl.setFormatter(fmt=msg_fmt)
    fhndl = logging.FileHandler(log_path, mode='a')
    fhndl.setFormatter(fmt=msg_fmt)
    logger.addHandler(strhndl)
    logger.addHandler(fhndl)

    logger.info('Starting Fuzzy Hasher v. {}'.format(__date__))
    logger.debug('System ' + sys.platform)
    logger.debug('Version ' + sys.version.replace("\n", " "))

    logger.info('Script Starting')
    main(args.PATH, args.output_type)
    logger.info('Script Completed')
