import os, json, shutil, time, fcntl, idontspeakssl

def prepare_output_directory(output_path, scope, report_format=None):
	result_directory = "{}/idontspeakssl_{}_results".format(output_path, time.strftime("%Y%m%d%I%M%S%p"))
	os.mkdir(result_directory)
	#os.mkdir("{}/sslyze_results".format(result_directory))
	if(report_format):
		if('web' in report_format):
			os.mkdir("{}/web".format(result_directory))
		if('textile' in report_format):
			os.mkdir("{}/textile".format(result_directory))
			os.mkdir("{}/spreadsheet".format(result_directory))
	init_status_file(result_directory, scope)
	return result_directory

def get_resource_path(filename):
	return os.path.join(os.path.dirname(idontspeakssl.__file__), 'data', 'resources', 'bin', filename)

def copyJSCSS(web_report_output_folder):
	shutil.copytree('resources/web_report', "{}/html".format(web_report_output_folder))

def extract_host_and_port(host_port):
	temp = host_port.split('_')
	return temp[0], temp[1]

def capitalize_sentence(sentense):
	words = sentense.split()
	for i in range(0, len(words)):
		words[i] = words[i].capitalize()
	return " ".join(words)

def udpate_status(status_file_path, module_data, module):
	lock_file_path = "{}.lock".format(status_file_path)
	while True:
		status_file_lock = open(lock_file_path, 'r')
		try:
			fcntl.flock(status_file_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
			with open(status_file_path, "r+") as status_file:
				data = json.load(status_file)
				status_file.seek(0)
				data[module].update(module_data)
				json.dump(data, status_file)
			fcntl.flock(status_file_lock, fcntl.LOCK_UN)
			return
		except:
			time.sleep(0.1)
		status_file_lock.close()

def init_status_file(result_directory, scope):
	status_file_path = "{}/status.json".format(result_directory)
	data = {
		"report folder": result_directory,
		"scope": scope,
		"scanner results":{},
		"analyzer results":{}
	}
	with open( status_file_path, 'w') as status_file:
		json.dump(data, status_file)

def extract_scope_from_status(status_file_path):
	scope = []
	with open(status_file_path,'r') as status_file:
		data = json.load(status_file)
	for target in data['scope']:
		scope.append("_".join([target['host'], target['port']]))
	return scope

def load_json_file(file_path):
    with open(file_path) as config_file_content:
        json_data = json.load(config_file_content)
    return json_data

def load_config_file(filename):
    file_path = os.path.join(os.path.dirname(idontspeakssl.__file__), 'data', 'config', filename)
    return load_json_file(file_path)


def copy_js_css(report_folder):
    if(not os.path.isdir("{}/html".format(report_folder))):
        resources_path = os.path.join(os.path.dirname(idontspeakssl.__file__), 'data', 'resources' , 'web_report')
        shutil.copytree(resources_path, "{}/html/".format(report_folder))
