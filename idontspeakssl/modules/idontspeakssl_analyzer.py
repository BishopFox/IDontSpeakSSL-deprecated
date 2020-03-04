import os, json



class IDontSpeaksSSLAnalyzer():

	def __init__(self, result_directory, full_target_list):
		self.result_directory = result_directory
		self.status_file_path = "{}/status.json".format(self.result_directory)
		self.full_target_list = self.extract_target_list()
		if(not "{}/status.json.lock".format(self.result_directory)):
			open("{}/status.json.lock".format(self.result_directory), 'a').close()
	
	def extract_target_list(self):
		scope = []
		with open(self.status_file_path,'r') as status_file:
			data = json.load(status_file)
		for target in data['scope']:
			scope.append("_".join([target['host'], target['port']]))
		return scope


