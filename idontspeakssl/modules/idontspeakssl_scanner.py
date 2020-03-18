from queue import Queue
from threading import Thread
from termcolor import colored, cprint
from idontspeakssl.common.utils  import udpate_status
from sslyze.server_connectivity_tester import ServerConnectivityTester, ServerConnectivityError
from sslyze.plugins.openssl_cipher_suites_plugin import Sslv20ScanCommand, Sslv30ScanCommand, Tlsv10ScanCommand, Tlsv11ScanCommand, Tlsv12ScanCommand, Tlsv13ScanCommand
from sslyze.plugins.certificate_info_plugin import CertificateInfoScanCommand
from sslyze.plugins.compression_plugin import CompressionScanCommand
from sslyze.plugins.fallback_scsv_plugin import FallbackScsvScanCommand
from sslyze.plugins.heartbleed_plugin import HeartbleedScanCommand
from sslyze.plugins.early_data_plugin import EarlyDataScanCommand
from sslyze.plugins.openssl_ccs_injection_plugin import OpenSslCcsInjectionScanCommand
from sslyze.plugins.robot_plugin import RobotScanCommand
from sslyze.plugins.session_renegotiation_plugin import SessionRenegotiationScanCommand
from sslyze.plugins.session_resumption_plugin import SessionResumptionSupportScanCommand
from sslyze.synchronous_scanner import SynchronousScanner
from cryptography.hazmat.primitives.serialization import Encoding


class IDontSpeaksSSLScanner():

	def __init__(self, result_directory, full_target_list, nb_worker):
		self.result_directory = result_directory
		self.full_target_list = full_target_list
		self.status_file_path = "{}/status.json".format(self.result_directory)
		open("{}/status.json.lock".format(self.result_directory), 'a').close()
		self.nb_worker = nb_worker

	def test_server_connectivity(self, address, port, service_type=None):
		if(service_type):
			cprint("Type undefined for {} port: {}".format(address, port), 'yellow')
		else:
			server_tester = ServerConnectivityTester(
				hostname=address,
				port=port
			)
			try:
				server_info = server_tester.perform()
				return server_info
			except ServerConnectivityError as e:
				cprint("Error: {}".format(e), "yellow")
		return None

	def run_cipher_suite_commands(self, server_info, synchronous_scanner):
		cipher_scan_results = {}
		commands = [
			Sslv20ScanCommand(),
			Sslv30ScanCommand(),
			Tlsv10ScanCommand(),
			Tlsv11ScanCommand(),
			Tlsv12ScanCommand(),
			Tlsv13ScanCommand()
			]
		for command in commands:
			scan_result = synchronous_scanner.run_scan_command(server_info, command)
			ciphers = []
			for cipher in scan_result.accepted_cipher_list:
				ciphers.append({
						"name":cipher.name,
						"key_size":cipher.key_size
					})
			cipher_scan_results[scan_result.scan_command.get_title()] = ciphers
		#print('ciphers obtained for ',server_info)
		return cipher_scan_results

	def run_certificate_command(self, server_info, synchronous_scanner):
		certificate_chain = {}
		command = CertificateInfoScanCommand()
		scan_result = synchronous_scanner.run_scan_command(server_info, command)
		i=0
		for certificate in scan_result.received_certificate_chain:
			certificate_chain[i] = {"pem":certificate.public_bytes(Encoding.PEM).decode("ascii")}
			if(i > 0):
				certificate_chain[i]['is_CA'] = True
			else:
				certificate_chain[i]['is_CA'] = False
			i += 1
		trusted_chain = False
		if(scan_result.verified_certificate_chain):
			trusted_chain = True
		result_by_trusted_store = {}
		for store_result in scan_result.path_validation_result_list:
			store_name  = store_result.trust_store.name  + store_result.trust_store.version
			result_by_trusted_store[store_name] = store_result.was_validation_successful
		return {"certificate_chain":certificate_chain,
			"is_chain_trusted": trusted_chain,
			"oscp_response":scan_result.ocsp_response_is_trusted,
			"result_by_trusted_store": result_by_trusted_store}


	def run_compression_command(self, server_info, synchronous_scanner):
		command = CompressionScanCommand()
		try:
			scan_result = synchronous_scanner.run_scan_command(server_info, command)
			#print('Compression obtained for ',server_info)
			return scan_result.compression_name
		except:
			#print('Compression obtained for ',server_info)
			return None

	def run_fallback_scsv_command(self, server_info, synchronous_scanner):
		command = FallbackScsvScanCommand()
		try:
			scan_result = synchronous_scanner.run_scan_command(server_info, command)
			#print('fallback_scsv obtained for ',server_info)
			return scan_result.supports_fallback_scsv
		except:
			#print('fallback_scsv obtained for ',server_info)
			return None

	def run_heartbleed_command(self, server_info, synchronous_scanner):
		command = HeartbleedScanCommand()
		try:
			scan_result = synchronous_scanner.run_scan_command(server_info, command)
			#print('heartbleed obtained for ',server_info)
			return scan_result.is_vulnerable_to_heartbleed
		except:
			#print('heartbleed obtained for ',server_info)
			return None

	def run_early_data_command(self, server_info, synchronous_scanner):
		command = EarlyDataScanCommand()
		try:
			scan_result = synchronous_scanner.run_scan_command(server_info, command)
			#print('early_data obtained for ',server_info)
			return scan_result.is_early_data_supported
		except:
			#print('early_data obtained for ',server_info)
			return None

	def run_openssl_ccs_injection_command(self, server_info, synchronous_scanner):
		command = OpenSslCcsInjectionScanCommand()
		try:
			scan_result = synchronous_scanner.run_scan_command(server_info, command)
			#print('openssl_ccs_injection obtained for ',server_info)
			return scan_result.is_vulnerable_to_ccs_injection
		except:
			#print('openssl_ccs_injection obtained for ',server_info)
			return None

	def run_robot_command(self, server_info, synchronous_scanner):
		command = RobotScanCommand()
		try:
			scan_result = synchronous_scanner.run_scan_command(server_info, command)
			#print('robot obtained for ',server_info)
			return scan_result.robot_result_enum.value
		except:
			#print('robot obtained for ',server_info)
			return None

	def run_session_renegotiation_command(self, server_info, synchronous_scanner):
		command = SessionRenegotiationScanCommand()
		try:
			scan_result = synchronous_scanner.run_scan_command(server_info, command)
			#print('session_renegotiation obtained for ',server_info)
			return {"supports_secure_renegotiation": scan_result.supports_secure_renegotiation,
			"accepts_client_renegotiation":scan_result.accepts_client_renegotiation}
		except:
			#print('session_renegotiation obtained for ',server_info)
			return None

	def run_session_resumption_command(self, server_info, synchronous_scanner):
		command = SessionResumptionSupportScanCommand()
		scan_result = synchronous_scanner.run_scan_command(server_info, command)
		#print('session_resumption obtained for ',server_info)
		return {"errored_resumptions_list":scan_result.errored_resumptions_list,
			"attempted_resumptions_nb": scan_result.attempted_resumptions_nb,
			"failed_resumptions_nb": scan_result.failed_resumptions_nb,
			"is_ticket_resumption_supported":scan_result.is_ticket_resumption_supported,
			"successful_resumptions_nb":scan_result.successful_resumptions_nb,
			"ticket_resumption_error":scan_result.ticket_resumption_error,
			"ticket_resumption_failed_reason":scan_result.ticket_resumption_failed_reason}

	def run_sslyze_commands(self, server_info):
		full_scan_results = {}
		synchronous_scanner = SynchronousScanner()
		full_scan_results["Cipher suites"] = self.run_cipher_suite_commands(server_info, synchronous_scanner)
		full_scan_results["Certificates"] = self.run_certificate_command(server_info, synchronous_scanner)
		full_scan_results["Compression"] = self.run_compression_command(server_info, synchronous_scanner)
		full_scan_results["Fallback SCSV"] = self.run_fallback_scsv_command(server_info, synchronous_scanner)
		full_scan_results["Heartbleed"] = self.run_heartbleed_command(server_info, synchronous_scanner)
		full_scan_results["Early Data"] = self.run_early_data_command(server_info, synchronous_scanner)
		full_scan_results["CCS Injection"] = self.run_openssl_ccs_injection_command(server_info, synchronous_scanner)
		full_scan_results["Robot"] = self.run_robot_command(server_info, synchronous_scanner)
		full_scan_results["Session Renegotiation"] = self.run_session_renegotiation_command(server_info, synchronous_scanner)
		full_scan_results["Session Resumption"] = self.run_session_resumption_command(server_info, synchronous_scanner)
		return full_scan_results

	def scan_target(self, queue):
		while(not queue.empty()):
			scan = {}
			target, target_id, target_nb = queue.get()
			cprint("[-] {}/{} Scanning {}".format(target_id, target_nb, target), 'blue')
			target_address = target["host"]
			target_port = target["port"]
			#target_proto = target["proto"]
			server_info = self.test_server_connectivity(target_address, target_port)
			if(server_info):
				scan["_".join([target_address, target_port])] = self.run_sslyze_commands(server_info)
			else:
				scan["_".join([target_address, target_port])] = None
			udpate_status(self.status_file_path, scan, "scanner results")
			cprint("[+] {}/{} {} scan done".format(target_id, target_nb, target), 'green')
			queue.task_done()
		return

	def run(self):
		queue = Queue()
		#ipnb = sum(1 for line in open(iplist))
		target_nb = len(self.full_target_list)-1
		i=0
		for target in self.full_target_list:
			queue.put((target, i, target_nb))
			i+=1
		for x in range(self.nb_worker):
			worker = Thread(target=self.scan_target, args=(queue,))
			worker.setDaemon(True)
			worker.start()
		queue.join()
		return
