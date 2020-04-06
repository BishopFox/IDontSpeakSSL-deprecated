from OpenSSL import crypto
from datetime import datetime
from idontspeakssl.common.utils import load_config_file

class CertificateChecker():

	# To Do
	# Add the possibility to add a 
	@staticmethod
	def verify_trust_chain(certificate, ca):
		cert = crypto.load_certificate(crypto.FILETYPE_PEM, certificate)
		store = crypto.X509Store()
		store_ctx = crypto.X509StoreContext(store, cert)
		result = store_ctx.verify_certificate()

	def check_certificate_key_size(certificate):
		key_size =  certificate.get_pubkey().bits()
		signature = certificate.get_signature_algorithm().decode("utf-8")
		certificate_key_size_config = load_config_file('certificate_key_size.json')
		for kex, min_size in certificate_key_size_config.items():
			if(kex in signature):
				if(key_size < min_size):
					return {"Certificate_key_too_small" : True,
						"certificate_key_size": key_size,
						"certificate_kex_algorithm":kex}
		return {}

	def get_cert_ttl_config():
		config = load_config_file('certificates_TTL.json')
		if(config['certificate TTL unit'] == 'y'):
			return config["certitifcate TTL"] * 365
		elif(config['certificate TTL unit'] == 'm'):
			return config["certitifcate TTL"] * 30
		elif(config['certificate TTL unit'] == 'd'):
			return config["certitifcate TTL"]

	def check_certificate_TTL(not_after, not_before):
		cert_ttl_days = abs((not_after - not_before).days)
		cert_ttl_config = CertificateChecker.get_cert_ttl_config()
		if(cert_ttl_days>cert_ttl_config):
			return {'certificate_ttl_too_long': True,
			'certificate_ttl': cert_ttl_days}
		return {}

	def check_early_deployment(time_now, not_before):
		before = (time_now - not_before).days
		if(before < 0):
			return {'deployment_before_delivery_date': before.days}
		return {}

	def check_certificate_expiration(certificate, time_now, not_after):
		if(certificate.has_expired()):
			expired_since =  time_now - not_after
			return {'certificate_expired': True,
				'expired_since': expired_since.days,
				'expiration_date': not_after.strftime("%m/%d/%Y")}
		return {}

	@classmethod
	def check_certificate_dates(cls, certificate):
		findings = {}
		not_after = datetime.strptime(certificate.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
		not_before = datetime.strptime(certificate.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')
		time_now = datetime.now()
		findings.update(cls.check_certificate_expiration(certificate, time_now, not_after))
		findings.update(cls.check_early_deployment(time_now, not_before))
		findings.update(cls.check_certificate_TTL(not_after, not_before))

		return findings

	def check_certificate_signature(certificate):
		certificate_findings = {}
		certificate_signature_config = load_config_file('certificate_signature.json')
		cert_sign = certificate.get_signature_algorithm().decode("utf-8")
		if(cert_sign in certificate_signature_config['bad']):
			certificate_findings['insecure_certificate_signature'] = True
			certificate_findings['certificate_signature'] = cert_sign
		return certificate_findings

	@classmethod
	def analyze_certificate(cls, certificate_pem):
		certificate_findings = {}
		certificate = crypto.load_certificate(crypto.FILETYPE_PEM, certificate_pem)
		certificate_findings.update(cls.check_certificate_signature(certificate))
		certificate_findings.update(cls.check_certificate_dates(certificate))
		certificate_findings.update(cls.check_certificate_key_size(certificate))
		return certificate_findings

	@classmethod
	def extract_domains_from_cert(cls, target, certificate_pem, report_folder):
		domains = []
		certificate = crypto.load_certificate(crypto.FILETYPE_PEM, certificate_pem)
		ext_count = certificate.get_extension_count()
		for i in range(0,ext_count):
			try:
				extension = certificate.get_extension(i).__str__()
				# might be subject to error if pyopenssl change the representation of data
				# if it happens, use the extension,get_data() instead
				if(extension.startswith("DNS:")):
					for domain in extension.split(' '):
						domains.append(domain[4:])
			except:
				pass
		for subject_component in certificate.get_subject().get_components():
			if(b'CN' in subject_component):
				for CN_component in subject_component:
					if(not CN_component == b'CN'):
						domains.append(CN_component.decode('utf8'))
		if(domains):
			with open('{}/certificates_domains.txt'.format(report_folder), 'a') as domains_file:
				url = target.replace('_',':')
				domains_file.write("{}: {}".format(url, ", ".join(domains)))
