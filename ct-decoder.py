#!/usr/bin/env python3

import argparse
import json
import base64
from cryptography import x509


def logparse():

	"""
	This function takes in the known certificate tranparency loggers
	https://www.gstatic.com/ct/log_list/v3/all_logs_list.json

	Parses through them and returns the log_id and description of each (in a list). For the log_id, it will base64 decode them then
	converts it to hexadecimal

	Example:
	{
        "Log ID": "3b5377753e2db9804e8b305b06fe403b67d84fc3f4c7bd000d2d726fe1fad417",
        "Description": "Let's Encrypt 'Oak2024H1' log"
    }
	"""

	ct_logger_parsed = []

	with open("all_logs_list.json", "r") as json_file:
		ctloggers = json.load(json_file)

	for operator in ctloggers['operators']:
	    for log in operator['logs']:
	        log_id = log['log_id']
	        log_id = base64.b64decode(log_id.encode()).hex()
	        description = log['description']
	        ct_logger_parsed.append({"Log ID": log_id,"Description": description})
	
	ct_loggers_log_ids_json = json.dumps(ct_logger_parsed, indent=4)

	return ct_loggers_log_ids_json


def certdecode(filename):

	"""
	This function opens up the passed certificate and reads the Precertificate Signed Certificate Timestamps. 
	For each Signed Certificate Timestamp, it will take the log_id, decode them and add them to a list

	"""

	try:
		with open(filename, "rb") as cert_file:
			cert = x509.load_pem_x509_certificate(cert_file.read())

	except ValueError:
		with open(filename, "rb") as cert_file:
			cert = x509.load_der_x509_certificate(cert_file.read())

	print()			
	print("============================Certificate Details============================")	
	print(f"Serial Number: {cert.serial_number}")
	print(f"Subject: {cert.subject}")
	print(f"Issuer: {cert.issuer}")
	print("===========================================================================")
	print()

	sct = cert.extensions.get_extension_for_class(x509.PrecertificateSignedCertificateTimestamps)
	
	certificate_log_id_list = []

	for lid in sct.value:
		certificate_log_id_list.append(lid.log_id.hex())
		
	return certificate_log_id_list


	
def main():

	'''
	A Python-based Precertificate Signed Certificate Timestamp decoder and lookup tool
	'''

	argparse_main = argparse.ArgumentParser(description="A python-based Precertificate Signed Certificate Timestamp decoder and lookup tool")
	
	argparse_main.add_argument("-c","--certificate", help="Define X509 certificate to decode. Can be in PEM or DER.")
	args = argparse_main.parse_args()


	if args.certificate:
		#Run the logparse function on 'all_logs_list.json'
		try:
			ct_loggers_log_ids_json = logparse()
		except FileNotFoundError:
			print("Download the current loggers list found here: https://www.gstatic.com/ct/log_list/v3/all_logs_list.json. Ensure that 'all_logs_list.json' is in this directory.")
		except UnboundLocalError:
			pass
	

		#Run the certdecode function to decode the SCTs in the certificate
		try:
			certificate_log_id_list = certdecode(args.certificate)
		except ValueError:
			print("File is not in PEM or DER")

		except FileNotFoundError:
			print("Certificate file could not be found. Please check the filename")


		#Determine if the log_ids found in the certificate match with the list of all log ids
		try:
			ct_loggers_log_ids_json = logparse()
			
			ct_loggers_log_ids_json = json.loads(ct_loggers_log_ids_json)

			matching_log_ids = []

			for certificate_log_id in certificate_log_id_list:
			    for ct_loggers_log_id in ct_loggers_log_ids_json:
			        if certificate_log_id == ct_loggers_log_id['Log ID']:
			            matching_log_ids.append(ct_loggers_log_id)

			print("Signed Certificate Timestamps")
			print()
			#Format matching_log_ids
			for item in matching_log_ids:
			    log_id = item['Log ID']
			    description = item['Description']
			    print(f"Log ID: {log_id}\nDescription: {description}\n")

		except FileNotFoundError:
			pass
		except UnboundLocalError:
			pass


if __name__ == '__main__':
	main()
