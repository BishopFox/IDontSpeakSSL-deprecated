import os, json, shutil, time
import fcntl

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

def copyJSCSS(web_report_output_folder):
	shutil.copytree('resources', "{}/html".format(web_report_output_folder))


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
		"scope": scope,
		"scanner results":{},
		"analyzer results":{}
	}
	with open( status_file_path, 'w') as status_file:
		json.dump(data, status_file)
