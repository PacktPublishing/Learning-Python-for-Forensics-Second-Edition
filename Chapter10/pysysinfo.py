"""Script to gather system information into a report."""
from __future__ import print_function
import argparse
import os
import platform
import sys

import psutil
if sys.version_info[0] == 2:
	import unicodecsv as csv
elif sys.version_info[0] == 3:
	import csv


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
__date__ = '20190120'
__description__ = ('This script collects information about '
    'active processes and system information for Windows '
	'and Linux')


def return_none():
	"""
	Returns a None value, but is callable.
	:return: None.
	"""
	return None


def read_proc_connections(proc):
	"""
	Read connection properties from a process.
	:param proc: An object representing a running process.
	:return conn_details: A list of process connection
	properties.
	"""
	conn_details = []
	for conn in proc.connections():
		conn_items = {}
		conn_items['fd'] = getattr(conn, 'fd', None)
		conn_items['status'] = getattr(conn, 'status', None)
		conn_items['local_addr'] = "{}:{}".format(
			getattr(conn.laddr, 'ip', ""), getattr(
			conn.laddr, 'port', ""))
		conn_items['remote_addr'] = "{}:{}".format(
			getattr(conn.raddr, 'ip', ""), getattr(
			conn.raddr, 'port', ""))

		conn_details.append(conn_items)
	return conn_details


def read_proc_files(proc):
	"""
	Read file properties from a process.
	:param proc: An object representing a running process.
	:return file_details: a list containing process details.
	"""
	file_details = []
	for handle in proc.open_files():
		handle_items = {}
		handle_items['fd'] = getattr(handle, 'fd', None)
		handle_items['path'] = getattr(handle, 'path', None)
		handle_items['position'] = getattr(
		handle, 'position', None)
		handle_items['mode'] = getattr(handle, 'mode', None)

		file_details.append(handle_items)

	return file_details


def get_pid_details(pid):
	"""
	Gather details on a specific pid.
	:param pid: an integer value of a pid to query for
	additional details.
	:return details: a dictionary of gathered information
	about the pid.
	"""
	details = {'name': '', 'exe': '', 'cmdline': '', 'pid': pid,
			   'ppid': 0, 'status': '', 'username': '',
			   'terminal': '', 'cwd': '', 'create_time': '',
			   'children': [],  # list of pid ints
			   'threads': [],  # list of thread ints
			   'files': [],	 # list of open files
			   'connections': [],  # list of network connections
			   '_errors': []
			  }
	try:
		proc = psutil.Process(pid)
	except psutil.NoSuchProcess:
		details['_errors'].append(
		(pid, 'Process no longer found'))
		return details
	except OSError:
		details['_errors'].append((pid, 'OSError'))
		return details

	for key in details:
		try:
			if key in ('pid', '_errors'):
				continue
			elif key == 'children':
				children = proc.children()
				details[key] = [c.pid for c in children]

			elif key == 'threads':
				threads = proc.threads()
				details[key] = [t.id for t in threads]
			elif key == 'connections':
				details[key] = read_proc_connections(proc)
			elif key == 'files':
				details[key] = read_proc_files(proc)
			else:
				details[key] = getattr(proc, key, return_none)()
		except psutil.AccessDenied:
			details[key] = []
			details['_errors'].append((key, 'AccessDenied'))
		except OSError:
			details[key] = []
			details['_errors'].append((key, 'OSError'))
		except psutil.NoSuchProcess:
			details['_errors'].append(
			(pid, 'Process no longer found'))
			break
	return details


def get_process_info():
	"""
	Gather details on running processes within the system.
	:return pid_info: A dictionary containing details of
	running processes.
	"""

	# List of PIDs
	pid_info = {}
	for pid in psutil.pids():
		pid_info[pid] = get_pid_details(pid)
	return pid_info


def wmi_info(outdir):
	"""
	Gather information available through Windows Management
	Interface. We recommend extending this script by adding
	support for other WMI modules -- Win32_PrintJob,
	Win32_NetworkAdapterConfiguration, Win32_Printer,
	Win32_PnpEntity (USB).
	:param outdir: The directory to write CSV reports to.
	:return: Nothing.
	"""

	wmi_dict = {"Users": [], "Shares": [], "Services": [],
	"Disks": [], "Event Log": []}
	conn = wmi.WMI()

	# See attributes for a given module like so: for user in
	# conn.Win32_UserAccount(); user._getAttributeNames()

	print("[+] Gathering information on Windows user profiles")
	for user in conn.Win32_UserAccount():
		wmi_dict["Users"].append({
			"Name": user.Name, "SID": user.SID,
			"Description": user.Description,
			"InstallDate": user.InstallDate,
			"Domain": user.Domain,
			"Local Account": user.LocalAccount,
			"Password Changeable": user.PasswordChangeable,
			"Password Required": user.PasswordRequired,
			"Password Expires": user.PasswordExpires,
			"Lockout": user.Lockout
		})

	print("[+] Gathering information on Windows shares")
	for share in conn.query("SELECT * from Win32_Share"):
		wmi_dict["Shares"].append({
			"Name": share.Name, "Path": share.Path,
			"Description": share.Description,
			"Status": share.Status,
			"Install Date": share.InstallDate})

	print("[+] Gathering information on Windows services")
	for service in conn.query(
	"SELECT * FROM Win32_Service WHERE State='Running'"):
		wmi_dict["Services"].append({
			"Name": service.Name,
			"Description": service.Description,
			"Start Mode": service.StartMode,
			"State": service.State,
			"Path": service.PathName,
			"System Name": service.SystemName})

	print("[+] Gathering information on connected drives")
	for disk in conn.Win32_DiskDrive():
		for partition in disk.associators(
		"Win32_DiskDriveToDiskPartition"):
			for logical_disk in partition.associators(
					"Win32_LogicalDiskToPartition"):
				wmi_dict["Disks"].append({
					"Physical Disk Name": disk.Name,
					"Bytes Per Sector": disk.BytesPerSector,
					"Sectors": disk.TotalSectors,
					"Physical S/N": disk.SerialNumber,
					"Disk Size": disk.Size,
					"Model": disk.Model,
					"Manufacturer": disk.Manufacturer,
					"Media Type": disk.MediaType,
					"Partition Name": partition.Name,
					"Partition Desc.": partition.Description,
					"Primary Partition": partition.PrimaryPartition,
					"Bootable": partition.Bootable,
					"Partition Size": partition.Size,
					"Logical Name": logical_disk.Name,
					"Volume Name": logical_disk.VolumeName,
					"Volume S/N": logical_disk.VolumeSerialNumber,
					"FileSystem": logical_disk.FileSystem,
					"Volume Size": logical_disk.Size,
					"Volume Free Space": logical_disk.FreeSpace})

	# Query for logon events type 4624
	print("[+] Querying the Windows Security Event Log "
	"for Event ID 4624")
	wmi_query = ("SELECT * from Win32_NTLogEvent WHERE Logfile="
	"'Security' AND EventCode='4624'")
	for logon in conn.query(wmi_query):
		wmi_dict["Event Log"].append({
			"Event Category": logon.CategoryString,
			"Event ID": logon.EventIdentifier,
			"Time Generated": logon.TimeGenerated,
			"Message": logon.Message})

	csv_writer(wmi_dict["Users"], outdir, "users.csv",
	sorted(wmi_dict["Users"][0].keys()))
	csv_writer(wmi_dict["Shares"], outdir, "shares.csv",
	sorted(wmi_dict["Shares"][0].keys()))
	csv_writer(wmi_dict["Services"], outdir, "services.csv",
	sorted(wmi_dict["Services"][0].keys()))
	csv_writer(wmi_dict["Disks"], outdir, "disks.csv",
	sorted(wmi_dict["Disks"][0].keys()))
	try:
		csv_writer(wmi_dict["Event Log"],outdir, "logonevent.csv",
		sorted(wmi_dict["Event Log"][0].keys()))
	except IndexError:
		print("No Security Event Log Logon events (Event ID "
		"4624). Make sure to run the script in an escalated "
		"command prompt")


def csv_writer(data, outdir, name, headers, **kwargs):
	"""
	The csv_writer function writes WMI or process information
	to a CSV output file.
	:param data: The dictionary or list containing the data to
	write to the CSV file.
	:param outdir: The directory to write the CSV report to.
	:param name: the name of the output CSV file.
	:param headers: the CSV column headers.
	:return: Nothing.
	"""
	out_file = os.path.join(outdir, name)

	if sys.version_info[0] == 2:
		csvfile = open(out_file, "wb")
	elif sys.version_info[0] == 3:
		csvfile = open(out_file, "w", newline='',
		encoding='utf-8')

	if 'type' in kwargs:
		with csvfile:
			csvwriter = csv.DictWriter(csvfile, fields,
			extrasaction='ignore')
			csvwriter.writeheader()
			csvwriter.writerows([v for v in data.values()])

	else:
		with csvfile:
			csvwriter = csv.writer(csvfile)
			csvwriter.writerow(headers)
			for row in data:
				csvwriter.writerow([row[x] for x in headers])


if __name__ == '__main__':
	parser = argparse.ArgumentParser(description=__description__,
                                     epilog='Developed by ' +
                                     __author__ + ' on ' +
                                     __date__)
	parser.add_argument('OUTPUT_DIR',
	help="Path to output directory. Will create if not found.")
	args = parser.parse_args()

	if not os.path.exists(args.OUTPUT_DIR):
		os.makedirs(args.OUTPUT_DIR)

	if 'windows' in platform.system().lower():
		try:
			import wmi
		except ImportError:
			print("Install the wmi and pywin32 modules. "
			"Exiting...")
			sys.exit(1)
		wmi_info(args.OUTPUT_DIR)

	# Run data gathering function
	print("[+] Gathering current active processes information")
	pid_data = get_process_info()
	fields = ['pid', 'name', 'exe', 'ppid', 'cmdline',
	'username', 'cwd', 'create_time', '_errors']

	# Generate reports from gathered details
	csv_writer(pid_data, args.OUTPUT_DIR, 'pid_summary.csv',
	fields, type='DictWriter')
