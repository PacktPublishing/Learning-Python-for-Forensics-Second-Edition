"""Second iteration of the Bitcoin JSON transaction parser."""
import argparse
import json
import logging
import sys
import os
import urllib.request
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


def main(address):
	"""
	The main function handles coordinating logic
	:param address: The Bitcoin Address to lookup
	:return: Nothing
	"""
	logging.info('Initiated program for {} address'.format(
	address))
	logging.info(
	'Obtaining JSON structured data from blockchain.info')
	raw_account = get_address(address)
	account = json.loads(raw_account.read())
	print_transactions(account)


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
		return urllib.request.urlopen(formatted_url)
	except urllib.error.URLError as e:
		logging.error('URL Error for {}'.format(formatted_url))
		if hasattr(e, 'code') and hasattr(e, 'headers'):
			logging.debug('{}: {}'.format(e.code, e.reason))
			logging.debug('{}'.format(e.headers))
		print('Received URL Error for {}'.format(formatted_url))
		logging.info('Program exiting...')
		sys.exit(1)


def print_transactions(account):
	"""
	The print_transaction function is responsible for presenting
	transaction details to end user.
	:param account: The JSON decoded account and transaction data
	:return: Nothing
	"""
	logging.info(
	'Printing account and transaction data to console.')
	print_header(account)
	print('Transactions')
	for i, tx in enumerate(account['txs']):
		print('Transaction #{}'.format(i))
		print('Transaction Hash:', tx['hash'])
		print('Transaction Date: {}'.format(
		unix.unix_converter(tx['time'])))
		for output in tx['out']:
			inputs = get_inputs(tx)
			if len(inputs) > 1:
				print('{} --> {} ({:.8f} BTC)'.format(
				' & '.join(inputs), output['addr'],
				output['value'] * 10**-8))
			elif len(inputs) == 1:
				print('{} --> {} ({:.8f} BTC)'.format(
				''.join(inputs), output['addr'],
				output['value'] * 10**-8))
			else:
				logging.warn(
				'Detected 0 inputs for transaction {}').format(
				tx['hash'])
				print('Detected 0 inputs for transaction.')

		print('{:=^22}\n'.format(''))


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
	return inputs

if __name__ == '__main__':
	# Run this code if the script is run from the command line.
	parser = argparse.ArgumentParser(
	description='BTC Address Lookup',
	epilog='Developed by ' + __author__ + ' on ' + __date__)

	parser.add_argument('ADDR', help='Bitcoin Address')
	parser.add_argument('-l', help="""Specify log directory.
	Defaults to current working directory.""")

	args = parser.parse_args()

	# Set up Log
	if args.l:
		if not os.path.exists(args.l):
			os.makedirs(args.l)
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
	main(args.ADDR)
