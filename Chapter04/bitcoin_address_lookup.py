"""Final iteration of the Bitcoin JSON transaction parser."""
from __future__ import print_function
import argparse
import csv
import json
import logging
import sys
import os
if sys.version_info[0] == 2:
	from urllib2 import urlopen
	from urllib2 import URLError
elif sys.version_info[0] == 3:
	from urllib.request import urlopen
	from urllib.error import URLError
else:
	print("Unsupported Python version. Exiting..")
	sys.exit(1)
import unix_converter as unix

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

__author__ = 'Preston Miller & Chapin Bryce'
__date__ = '20180729'
__description__ = """This scripts downloads address transactions
 using blockchain.info public APIs"""


def main(address, output_dir):
	"""
	The main function handles coordinating logic
	:param address: The Bitcoin Address to lookup
	:param output_dir: The output directory to write the CSV results
	:return: Nothing
	"""
	logging.info('Initiated program for {} address'.format(address))
	logging.info('Obtaining JSON structured data from blockchain.info')
	raw_account = get_address(address)
	account = json.loads(raw_account.read())
	print_header(account)
	parse_transactions(account, output_dir)


def get_address(address):
	"""
	The get_address function uses the blockchain.info Data API
	to pull pull down account information and transactions for
	address of interest
	:param address: The Bitcoin Address to lookup
	:return: The response of the url request
	"""
	url = 'https://blockchain.info/address/{}?format=json'
	formatted_url = url.format(address)
	try:
		return urlopen(formatted_url)
	except URLError as e:
		logging.error('URL Error for {}'.format(formatted_url))
		if hasattr(e, 'code') and hasattr(e, 'headers'):
			logging.debug('{}: {}'.format(e.code, e.reason))
			logging.debug('{}'.format(e.headers))
		print('Received URL Error for {}'.format(formatted_url))
		logging.info('Program exiting...')
		sys.exit(2)


def parse_transactions(account, output_dir):
	"""
	The parse_transactions function appends transaction data into a
	nested list structure so it can be successfully used by the
	csv_writer function.
	:param account: The JSON decoded account and transaction data
	:param output_dir: The output directory to write the CSV
	results
	:return: Nothing
	"""
	msg = 'Parsing transactions...'
	logging.info(msg)
	print(msg)
	transactions = []
	for i, tx in enumerate(account['txs']):
		transaction = []
		outputs = {}
		inputs = get_inputs(tx)
		transaction.append(i)
		transaction.append(unix.unix_converter(tx['time']))
		transaction.append(tx['hash'])
		transaction.append(inputs)
		for output in tx['out']:
			outputs[output['addr']] = output['value'] * 10**-8
		transaction.append('\n'.join(outputs.keys()))
		transaction.append(
		'\n'.join(str(v) for v in outputs.values()))
		transaction.append('{:.8f}'.format(sum(outputs.values())))
		transactions.append(transaction)
	csv_writer(transactions, output_dir)


def print_header(account):
	"""
	The print_header function prints overall header information
	containing basic address information.
	:param account: The JSON decoded account and transaction data
	:return: Nothing
	"""
	print('Address:', account['address'])
	print('Current Balance: {:.8f} BTC'.format(
	account['final_balance'] * 10**-8))
	print('Total Sent: {:.8f} BTC'.format(
	account['total_sent'] * 10**-8))
	print('Total Received: {:.8f} BTC'.format(
	account['total_received'] * 10**-8))
	print('Number of Transactions:', account['n_tx'])
	
	print('{:=^22}\n'.format(''))


def get_inputs(tx):
	"""
	The get_inputs function is a small helper function that returns
	input addresses for a given transaction
	:param tx: A single instance of a Bitcoin transaction
	:return: inputs, a list of inputs
	"""
	inputs = []
	for input_addr in tx['inputs']:
			inputs.append(input_addr['prev_out']['addr'])
	if len(inputs) > 1:
		input_string = '\n'.join(inputs)
	else:
		input_string = ''.join(inputs)
	return input_string


def csv_writer(data, output_dir):
	"""
	The csv_writer function writes transaction data into a CSV file
	:param data: The parsed transaction data in nested list
	:param output_dir: The output directory to write the CSV
	results
	:return: Nothing
	"""
	logging.info('Writing output to {}'.format(output_dir))
	print('Writing output.')
	headers = ['Index', 'Date', 'Transaction Hash',
	'Inputs', 'Outputs', 'Values', 'Total']
	try:
		if sys.version_info[0] == 2:
			csvfile = open(output_dir, 'wb')
		else:
			csvfile = open(output_dir, 'w', newline='')
		with csvfile:
			writer = csv.writer(csvfile)
			writer.writerow(headers)
			for transaction in data:
				writer.writerow(transaction)
			csvfile.flush()
			csvfile.close()
	except IOError as e:
		logging.error("""Error writing output to {}.
		\nGenerated message: {}.""".format(e.filename,
		e.strerror))
		print("""Error writing to CSV file.
		Please check output argument {}""".format(e.filename))
		logging.info('Program exiting.')
		sys.exit(1)
	logging.info('Program exiting.')
	print('Program exiting.')
	sys.exit(0)

if __name__ == '__main__':
	# Run this code if the script is run from the command line.
	parser = argparse.ArgumentParser(
	description='BTC Address Lookup',
	epilog='Developed by ' + __author__ + ' on ' + __date__)

	parser.add_argument('ADDR', help='Bitcoin Address')
	parser.add_argument('OUTPUT', help='Output CSV file')
	parser.add_argument('-l', help="""Specify log directory.
	Defaults to current working directory.""")

	args = parser.parse_args()

	# Set up Log
	if args.l:
		if not os.path.exists(args.l):
			os.makedirs(args.l)	 # create log directory path
		log_path = os.path.join(args.l, 'btc_addr_lookup.log')
	else:
		log_path = 'btc_addr_lookup.log'
	logging.basicConfig(
	filename=log_path, level=logging.DEBUG,
	format='%(asctime)s | %(levelname)s | %(message)s',
	filemode='w')

	logging.info('Starting Bitcoin Address Lookup')
	logging.debug('System ' + sys.platform)
	logging.debug('Version ' + sys.version)

	# Print Script Information
	print('{:=^22}'.format(''))
	print('{}'.format('Bitcoin Address Lookup'))
	print('{:=^22} \n'.format(''))

	# Run main program
	main(args.ADDR, args.OUTPUT)
