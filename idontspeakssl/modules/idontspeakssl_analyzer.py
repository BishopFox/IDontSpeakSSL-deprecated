import os, json
from idontspeakssl.common.utils import extract_scope_from_status, load_config_file, extract_host_and_port, udpate_status
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
				self.analyze_ciphers(target, scanner_results)
				self.analyze_certificates(target, scanner_results)
				self.analyze_heartbleed(target, scanner_results)
				self.analyze_sweet32(target, scanner_results)
				self.analyze_lucky13(target, scanner_results)
				self.analyze_DROWN(target, scanner_results)
				self.analyze_POODLE(target, scanner_results)
				self.analyze_fallback_SCSV(target, scanner_results)
				self.analyze_bar_mitsvah(target, scanner_results)
				self.analyze_ccs_injection(target, scanner_results)
		
		self.summary_of_findings()
		os.remove("{}/status.json.lock".format(self.result_directory))

	def summary_of_findings(self):
		self.findings['summary'] = {
			'protocols':[],
			'cipher_suites':[],
			'certificates':[],
			'vulnerabilities':{}
			}
		for host, host_findings in self.findings['hosts'].items():
			host, port = extract_host_and_port(host)
			if('protocols' in host_findings.keys()):
				
				self.findings['summary']['protocols'].append({
					'host':host,
					'port':port
				})
			if('cipher suites' in host_findings.keys()):
				self.findings['summary']['cipher_suites'].append({
					'host':host,
					'port':port
				})
			if('certificates' in host_findings.keys()):
				self.findings['summary']['certificates'].append({
					'host':host,
					'port':port
				})
			non_vulnerabilities = ['certificates', 'protocols',
				'cipher suites']
			vulns = list(set(host_findings.keys()) - set(non_vulnerabilities))
			for vuln in vulns:
				if vuln not in self.findings['summary']['vulnerabilities'].keys():
					self.findings['summary']['vulnerabilities'][vuln] = []
					self.findings['summary']['vulnerabilities'][vuln].append({
						'host':host,
						'port':port
					})
				else:
					self.findings['summary']['vulnerabilities'][vuln].append({
						'host':host,
						'port':port
					})
			udpate_status(self.status_file_path, self.findings, "analyzer results")



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
		cprint("Unkown protocol {}".format(protocol), 'red')
	
	def  analyze_protocols(self, target, scanner_results):
		bad_protocols_config = load_config_file('protocols.json')['bad']
		protocol_findings = []
		for protocol, ciphers in scanner_results["Cipher suites"].items():
			if(ciphers):
				if(protocol in bad_protocols_config):
					protocol_findings.append(self.get_simplified_protocol_name(protocol))
		if(protocol_findings):
			self.add_host_findings(target, "protocols", protocol_findings)

	def  analyze_ciphers(self, target, scanner_results):
		cipher_suites_config = load_config_file('cipher_suites.json')
		cipher_suites_findings = []
		for ciphers in scanner_results["Cipher suites"].values():
			if(ciphers):
				for cipher in ciphers:
					if(cipher['name'] in cipher_suites_config['rejected'].keys()):
						cipher_suites_findings.append(cipher['name'])
		if(cipher_suites_findings):
			self.add_host_findings(target, "cipher suites", cipher_suites_findings)

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
			self.add_host_findings(target, 'certificates', certificate_chain_findings)
	
	# https://stackoverflow.com/questions/30700348/how-to-validate-verify-an-x509-certificate-chain-of-trust-in-python/49282746#49282746
	def analyze_heartbleed(self, target, scanner_results):
		if(scanner_results['Heartbleed']):
			heartbleed_finding = HeartbleedPoC.heartbleed_demo(target, self.result_directory)
			self.add_host_findings(target, 'heartbledd', heartbleed_finding)
	
	def analyze_sweet32(self, target, scanner_results):
		sweet32_ciphers = ["3DES", "RC2", "IDEA"]
		sweet32_findings = []
		for ciphers in scanner_results["Cipher suites"].values():
			if(ciphers):
				for cipher in ciphers:
					for sweet32_pattern in sweet32_ciphers:
						if(sweet32_pattern in cipher['name']):
							sweet32_findings.append(cipher['name'])
		if(sweet32_findings):
			self.add_host_findings(target, "sweet32", sweet32_findings)

	def analyze_lucky13(self, target, scanner_results):
		lucky13_findings = []
		for protocol, ciphers in scanner_results["Cipher suites"].items():
			if((protocol == "TLSV1 Cipher Suites" or
				protocol == "TLSV1_1 Cipher Suites" or
				protocol == "TLSV1_2 Cipher Suites") and ciphers):
				for cipher in ciphers:
					if("CBC" in cipher['name']):
						lucky13_findings.append(cipher['name'])
		if(lucky13_findings):
			self.add_host_findings(target, "lucky13", lucky13_findings)

	def analyze_DROWN(self, target, scanner_results):
		DROWN_findings = []
		for protocol in scanner_results["Cipher suites"].keys():
			for cipher in scanner_results["Cipher suites"]["SSLV2 Cipher Suites"]:
				print("Down cipher", cipher['name'])
				if("RSA" in cipher['name']):
					DROWN_findings.append(cipher['name'])
		if(DROWN_findings):
			self.add_host_findings(target, "DROWN", DROWN_findings)

	def analyze_POODLE(self, target, scanner_results):
		POODLE_findings = []
		for cipher in scanner_results["Cipher suites"]['SSLV3 Cipher Suites']:
			if("CBC" in cipher['name']):
				POODLE_findings.append(cipher['name'])
		if(POODLE_findings):
			self.add_host_findings(target, "POODLE", POODLE_findings)
	
	def analyze_fallback_SCSV(self, target, scanner_results):
		if(scanner_results["Fallback SCSV"]):
			self.add_host_findings(target, "Fallback SCSV", True)

	def analyze_BEAST(self, target, scanner_results):
		print("BEAST Detection not implemented on purpose, https://blog.qualys.com/ssllabs/2013/09/10/is-beast-still-a-threat.")

	# https://blog.qualys.com/ssllabs/2013/03/19/rc4-in-tls-is-broken-now-what
	# https://twitter.com/ioerror/status/398059565947699200
	# https://www.schneier.com/blog/archives/2013/03/new_rc4_attack.html
	# https://tools.ietf.org/html/rfc7465
	# https://en.wikipedia.org/wiki/Bar_mitzvah_attack
	def analyze_bar_mitsvah(self, target, scanner_results):
		bar_mitsvah_findings = {}
		for protocol, ciphers in scanner_results["Cipher suites"].items():
			for cipher in ciphers:
				if("RC4" in cipher['name']):
					bar_mitsvah_findings.setdefault(protocol,[]).append(cipher['name'])
		if(bar_mitsvah_findings):
			self.add_host_findings(target, "Bar Mitsvah", bar_mitsvah_findings)

	def analyze_ccs_injection(self, target, scanner_results):
		if(scanner_results["CCS Injection"]):
			self.add_host_findings(target, "CCS Injection", True)

	def analyze_CRIME(self, target, scanner_results):
		if(scanner_results["Compression"]):
			self.add_host_findings(target, "CRIME", True)

	# Can be used when sslyze version before 3.0.0 is used
	def analyze_LOGJAM(self, target, scanner_results):
		logjam_findings = {}
		for protocol, ciphers in scanner_results["Cipher suites"].items():
			for cipher in ciphers:
				if("EXPORT" in cipher['name'] and "DH" in cipher['name']):
					# missing data from connection in sslyze 2.1.4, seems fixed in 3.0.0
					# Update must be done when updating to support of sslyze 3.0.0
					logjam_findings.setdefault(protocol,[]).append(cipher['name'])
		if(logjam_findings):
			self.add_host_findings(target, "LOGJAM", logjam_findings)

	"""
	From SSLyze:
    VULNERABLE_WEAK_ORACLE = 1  #: The server is vulnerable but the attack would take too long
    VULNERABLE_STRONG_ORACLE = 2  #: The server is vulnerable and real attacks are feasible
    NOT_VULNERABLE_NO_ORACLE = 3  #: The server supports RSA cipher suites but does not act as an oracle
    NOT_VULNERABLE_RSA_NOT_SUPPORTED = 4  #: The server does not supports RSA cipher suites
    UNKNOWN_INCONSISTENT_RESULTS = 5  #: Could not determine whether the server is vulnerable or not
	"""
	def analyze_Robot(self, target, scanner_results):
		if(scanner_results["Robot"]< 3):
			self.add_host_findings(target, "Robot", True)
			

# renegotiation\fR Tests renegotiation vulnerabilities\. Currently there\'s a check for \fISecure Renegotiation\fR and for \fISecure Client\-Initiated Renegotiation\fR\. Please be aware that vulnerable servers to the latter can likely be DoSed very easily (HTTP)\. A check for \fIInsecure Client\-Initiated Renegotiation\fR is not yet implemented\.
# breach\fR Checks for BREACH (\fIBrowser Reconnaissance and Exfiltration via Adaptive Compression of Hypertext\fR) vulnerability\. As for this vulnerability HTTP level compression is a prerequisite it\'ll be not tested if HTTP cannot be detected or the detection is not enforced via \fB`\-\-assume\-http\fR\. Please note that only the URL supplied (normally "/" ) is being tested\.
# freak\fR Checks for FREAK vulnerability (\fIFactoring RSA Export Keys\fR) by testing for EXPORT RSA ciphers

# ticketbleed\fR Checks for Ticketbleed memory leakage in BigIP loadbalancers\.
# it's a vuln affecting only BigIP load balancer, so should it be part of this tool?
