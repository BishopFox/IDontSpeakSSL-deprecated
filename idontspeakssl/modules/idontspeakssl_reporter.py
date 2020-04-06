from idontspeakssl.common.utils import load_json_file, copy_js_css, capitalize_sentence, extract_host_and_port
from yattag import Doc, indent
from termcolor import colored, cprint

class IDontSpeaksSSLReporter:

	def __init__(self, result_directory):
		self.results = load_json_file("{}/status.json".format(result_directory))
		self.report_folder = result_directory

class IDontSpeaksSSLReporterHTML(IDontSpeaksSSLReporter):
	pass

	def run(self):
		self.doc = Doc()
		copy_js_css(self.report_folder)
		cprint("[-] Generating the HTML report...", 'blue')
		self.doc.asis('<!DOCTYPE html>')
		self.create_header()
		self.create_body()
		self.write_report()
		cprint("[+] Report generated.", 'green')
		cprint("[+] All results can be found in {}/report.html.".format(self.report_folder), 'green')

	def create_body(self):
		with self.doc.tag('body'):
			with self.doc.tag('div'):
				self.doc.attr(klass='container')
				self.doc.line('h1', 'IDontSpeakSSL Report')
				self.add_summary_section("Findings Summary", self.results['analyzer results']["summary"])
				self.add_hosts_section("Findings per Host", self.results['analyzer results']["hosts"])

	def add_summary_section(self, section, subsections):
		self.doc.line('h2', section)
		with self.doc.tag('div'):
			self.doc.attr(klass='panel-group')
			for subsection, instances in subsections.items():
				if instances:
					with self.doc.tag('div', klass='panel panel-default'):
						with self.doc.tag('div', klass='panel-heading'):
							with self.doc.tag('div', klass='panel-title'):
								with self.doc.tag('h4', klass='panel-title'):
									with self.doc.tag('a', ("data-toggle", "collapse"), ("href" ,"#{}".format(capitalize_sentence(subsection)))):
										self.doc.text("{}".format(capitalize_sentence(subsection)))
						with self.doc.tag('div'):
							self.doc.attr(klass='panel-collapse collapse', id='{}'.format(capitalize_sentence(subsection)))
							with self.doc.tag('div', klass='panel-body'):
								if(subsection != "vulnerabilities"):
									with self.doc.tag('ul'):
										for instance in instances:
											self.doc.line('li', "Host: {}, Port: {}".format(
												instance['host'],
												instance['port']
												))
								else:
									with self.doc.tag('ul'):
										for vulnerability_name, vulnerability_instance in instances.items():
												self.doc.line('li', "{}".format(vulnerability_name))
												with self.doc.tag('ul'):
													for location in vulnerability_instance:
														self.doc.line('li', "Host: {}, Port: {}".format(
														location['host'],
														location['port']
														))

	def add_hosts_section(self, section, hosts):
		self.doc.line('h2', section)
		with self.doc.tag('div'):
			self.doc.attr(klass='panel-group')
			for host, findings in hosts.items():
				if findings:
					with self.doc.tag('div', klass='panel panel-default'):
						with self.doc.tag('div', klass='panel-heading'):
							with self.doc.tag('div', klass='panel-title'):
								with self.doc.tag('h4', klass='panel-title'):
									with self.doc.tag('a', ("data-toggle", "collapse"), ("href" ,"#{}".format(host.replace(".", "_")))):
										instance_host, instance_port = extract_host_and_port(host)
										self.doc.text("Host: {}, Port: {}".format(instance_host, instance_port))
					
					with self.doc.tag('div'):
						self.doc.attr(klass='panel-collapse collapse', id='{}'.format(host.replace(".", "_")))
						with self.doc.tag('div', klass='panel-body'):
							for finding_type, finding_instance in findings.items():
								self.doc.text("{}".format(finding_type))
								if(isinstance(finding_instance, list)):
									with self.doc.tag('ul'):
										for instance in finding_instance:
											self.doc.line('li', "{}".format(instance))
								elif(isinstance(finding_instance, bool)):
									if(finding_instance):
										self.doc.text(": Vulnerable")


	def create_header(self):
		with self.doc.tag('head'):
			self.doc.line('title', 'IDontSpeakSSL Report')
			self.doc.stag('link', ("rel", "stylesheet"), ("href", "html/css/bootstrap.min.css") )
			self.doc.line('script', '', src="html/js/jquery.min.js")
			self.doc.line('script', '', src="html/js/bootstrap.min.js")

	def write_report(self):
		with open("{}/report.html".format(self.report_folder), 'w') as report:
			report.write(indent(self.doc.getvalue()))
