#!/usr/bin/env python3

from idontspeakssl.common.utils  import prepare_output_directory
from idontspeakssl.common.printer import print_start_message
from idontspeakssl.modules.idontspeakssl_scanner import IDontSpeaksSSLScanner
from idontspeakssl.modules.idontspeakssl_analyzer import IDontSpeaksSSLAnalyzer
from idontspeakssl.modules.idontspeakssl_reporter import IDontSpeaksSSLReporterHTML
from idontspeakssl.modules.nmap_parse import NmapParse
import os,  mmap, re, base64, sys, socket, ssl, shutil, time
from termcolor import colored, cprint
from os import listdir
from os.path import isfile, join

import click


findingConfig = {}
    
def file_to_scope(target_file_path):
    scope = []
    with open(target_file_path,'r') as target_file:
        for target in target_file:
            target =target.strip()
            if target !="":
                target_and_port = target.split(":")
                if(len(target_and_port)==1):
                    target_and_port.append("443")
                scope.append({
				"host":target_and_port[0],
				"port":target_and_port[1],
				"proto":"PLAIN_TLS"
				})
    return  scope

def string_to_scope(target_string):
	full_target_list = []
	for target in target_string.split(","):
		if target !="":
			target_and_port = target.split(":")    
			if len(target_and_port)==1:
				target_and_port.append("443")
			full_target_list.append({
				"host":target_and_port[0],
				"port":target_and_port[1],
				"proto":"PLAIN_TLS"
				})
	return full_target_list

def prepare_target_list(target_file_path=None, target_string=None):
	scope = []
	if(target_file_path):
		scope += file_to_scope(target_file_path)
	if target_string!=None:
		scope += string_to_scope(target_string)
	return scope


def generateList(scopePath):
    targetList = []
    with open(scopePath, "r") as targets:
        for target in targets:
            target=(target.strip()).split(":")
            if target[1]=="":
                targetList.append([target[0],"443"])
            else:
                targetList.append([target[0],target[1]])
    return targetList

def clearFolder(path):
    if(os.path.isdir(path)):
        for f in os.listdir(path):
            if(f != "SecureClientInitiatedRenegotiation.txt"):
                os.remove("{}/{}".format(path, f))

def generateReportFromScan(path):
    # Implement checks on file exist and might need to remove the generated
    targetlist = generateList("{}/scope.txt".format(path))
    config()
    clearAnalyzeFolder(path)
    AnalyzeScanFile(path)
    report = Report(path, targetlist)
    report.createReport()

def run_scanner(output_directory, scope, nb_worker):
	print_start_message()
	result_directory = prepare_output_directory(output_directory, scope)
	scanner = IDontSpeaksSSLScanner(result_directory, scope, nb_worker)
	scanner.run()
	analyzer = IDontSpeaksSSLAnalyzer(result_directory)
	analyzer.run()
	html_report = IDontSpeaksSSLReporterHTML(result_directory)
	html_report.run()
	#AnalyzeScanFile(scandir)
	#report = Report(scandir, targetlist)
	#report.createReport()

def print_help_msg(command):
    with click.Context(command) as ctx:
        click.echo(command.get_help(ctx))

@click.command()
@click.option('-f', 'target_file', help='File containing taget IPs or domain names list, one per line', type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True))
@click.option('-n', 'nmap_file', help='nmap scanner output, xml format', type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True))
@click.option('-i', '--ip', 'target_string', help='List of taget IPs or domain names')
@click.option('-o', '--output', 'output', help='Output directory where scans will be saved', type=click.Path(exists=True, file_okay=False, dir_okay=True, writable=True), required=True)
@click.option('-w', 'nb_worker', help='number of workers. Number of scan to run at the same time. By default defined to 8', default=8)
@click.option('-r', 'status_file_path', help='Generate a report from scan files. Take a path to the scan folder.')
def run(target_file, target_string, output, nb_worker, status_file_path, nmap_file):
	if(status_file_path):
		print('Not working yet')
		generateReportFromScan(status_file_path)
	else:
		if(target_file or target_string):
			scope = prepare_target_list(target_file, target_string)
			
		elif(nmap_file):
			scope = NmapParse.parse_nmap(nmap_file)
		else:
			print("Missing needed options.")
			print_help_msg(run)
			exit()
		run_scanner(output, scope, nb_worker)
if __name__ == "__main__":
	run()
