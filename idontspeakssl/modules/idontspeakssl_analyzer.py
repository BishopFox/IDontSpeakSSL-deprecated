import os, json
from idontspeakssl.common.utils import extract_scope_from_status, load_config_file
from idontspeakssl.modules.certificate_checker import CertificateChecker
from idontspeakssl.modules.heartbleed_poc import HeartbleedPoC
from termcolor import colored, cprint
from OpenSSL import crypto
from datetime import datetime

class IDontSpeaksSSLAnalyzer():

	def __init__(self, result_directory):
		self.result_directory = result_directory
		self.status_file_path = "{}/status.json".format(self.result_directory)
		with open(self.status_file_path, 'r') as json_data:
			self.status = json.load(json_data)
		self.full_target_list = extract_scope_from_status(self.status_file_path)
		if(not "{}/status.json.lock".format(self.result_directory)):
			open("{}/status.json.lock".format(self.result_directory), 'a').close()
		self.findings = {
			"hosts":{}
		}

	def run(self):
		for target, scanner_results in self.status["scanner results"].items():
			if(scanner_results):
				self.analyze_protocols(target, scanner_results)
				#self.analyze_ciphers(scanner_results)
				self.analyze_certificates(target, scanner_results)
				self.analyze_heartbleed(target, scanner_results)
		print(self.findings)

	def add_host_findings(self, host, category, instances):
		if host not in self.findings['hosts'].keys():
			self.findings['hosts'][host] = {}
		self.findings['hosts'][host][category] = instances

	def get_simplified_protocol_name(self, protocol):
		if(protocol == "SSLV2 Cipher Suites"):
			return "SSLv2"
		if(protocol == "SSLV3 Cipher Suites"):
			return "SSLv3"
		if(protocol == "TLSV1 Cipher Suites"):
			return "TLSv1.0"
		if(protocol == "TLSV1_1 Cipher Suites"):
			return "TLSv1.1"
		if(protocol == "TLSV1_2 Cipher Suites"):
			return "TLSv1.2"
		if(protocol == "TLSV1_3 Cipher Suites"):
			return "TLSv1.3"
		cprint("Unkown protol {}".format(protocol), 'red')
	
	def  analyze_protocols(self, target, scanner_results):
		bad_protocols_config = load_config_file('protocols.json')['bad']
		protocol_findings = []
		for protocol, ciphers in scanner_results["Cipher suites"].items():
			if(ciphers):
				if(protocol in bad_protocols_config):
					protocol_findings.append(self.get_simplified_protocol_name(protocol))
		if(protocol_findings):
			self.add_host_findings(target, "protocols", protocol_findings)

	def  analyze_ciphers(self, scanner_results):
		print("Ciphers")

	def analyze_certificates(self, target, scanner_results):
		certificate_chain_findings = {}
		if(not scanner_results['Certificates']['is_chain_trusted']):
			for certificate_id, certificate_data in scanner_results['Certificates']["certificate_chain"].items():
				if(certificate_data['is_CA']):
					certificate_chain_findings['CA_level_'+certificate_id] = CertificateChecker.analyze_certificate(certificate_data['pem'])
				else:
					certificate_chain_findings[target] = CertificateChecker.analyze_certificate(certificate_data['pem'])
					CertificateChecker.extract_domains_from_cert(target, certificate_data['pem'], self.result_directory)
		if(certificate_chain_findings):
			self.add_host_findings(target, 'certificate', certificate_chain_findings)
	
	# https://stackoverflow.com/questions/30700348/how-to-validate-verify-an-x509-certificate-chain-of-trust-in-python/49282746#49282746
	def analyze_heartbleed(self, target, scanner_results):
		if(scanner_results['Heartbleed']):
			heartbleed_finding = HeartbleedPoC.heartbleed_demo(target, self.result_directory)
			self.add_host_findings(target, 'heartbledd', heartbleed_finding)
