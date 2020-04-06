import xml.etree.ElementTree as ET 


"""
		if(protocol == "PLAIN_TLS"):
		if(protocol == "HTTPS"):
		if(protocol == "STARTTLS_SMTP"):
		if(protocol == "STARTTLS_XMPP_SERVER"):
		if(protocol == "STARTTLS_FTP"):
		if(protocol == "STARTTLS_POP3"):
		if(protocol == "STARTTLS_LDAP"):
		if(protocol == "STARTTLS_IMAP"):
		if(protocol == "STARTTLS_RDP"):
		if(protocol == "STARTTLS_POSTGRES"):
"""
class NmapParse():
	
	protocols = {
		"https":"HTTPS",
		"http":"PLAIN_TLS",
		"http-proxy":"HTTPS",
		"https-alt":"HTTPS",
		"smtp":"PLAIN_TLS",
		"imap":"PLAIN_TLS",
		"pop3":"PLAIN_TLS",
		"jabber":"PLAIN_TLS",
		"ldap":"STARTTLS_LDAP",
		"ldapssl":"STARTTLS_LDAP",
		"ms-wbt-server":"STARTTLS_RDP"
	}

	def get_protocol_method(protocol):
		if(protocol in NmapParse.protocols.keys()):
			return NmapParse.protocols[protocol]
		else:
			return "PLAIN_TLS"

	@classmethod
	def parse_nmap(cls, nmap_file_path):
		scope = []
		with open(nmap_file_path, 'r') as nmap_file:
			nmap_tree = ET.parse(nmap_file) 
		root = nmap_tree.getroot() 
		for host in root.findall("host"):
			for address in host.iter('address'):
				host_address = address.get('addr')
			host_hostnames = []
			for hostnames in host.iter('hostnames'):
				for hostname in hostnames.iter('hostname'):
					host_hostnames.append(hostname.get('name'))
			status=None
			for host_item in host.iter('status'):
				if(host_item.tag == "status"):
					status = host_item.get('state')
			if(status != "up"):
				print(status)
				continue
			for port in host.iter('port'):					
				for service in port.iter('service'):
					if('tunnel' in service.attrib and service.attrib['tunnel'] == 'ssl'):
						protocol = cls.get_protocol_method(service.attrib['name'])
						if(protocol):
							scope.append({
									"host":host_address,
									"port":port.get('portid'),
									"protocol":protocol
								})
					if(service.attrib['name'] == "smtp" and port.get('portid') != 25 and "tunnel" not in service.attrib ): 
						scope.append({
									"host":host_address,
									"port":port.get('portid'),
									"protocol":"STARTTLS_SMTP"
								})
					if(service.attrib['name'] == "jabber" and "tunnel" not in service.attrib ): 
						print(port)
		return scope
