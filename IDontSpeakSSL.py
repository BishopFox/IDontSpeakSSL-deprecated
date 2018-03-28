#!/usr/bin/env python3

import os,  mmap, argparse, re, base64, sys
from termcolor import colored, cprint

protocols = {}
flaws = {}
ciphers = {}
certificates = {}
configurations = {}


def scan(scandir, iplist, testssl):
    with open(iplist, 'r') as f:
            for ip in f:
                cprint("[-] Scanning {}".format(ip[:-1]), 'blue')
                os.system("{} --color 0 {} > {}/{}.txt".format(testssl, ip[:-1], scandir, ip[:-1]))  
                cprint("[-] {} scan done".format(ip[:-1]), 'green')




def writeResult(filename,ip):
    with open(filename, "a") as resfile:
        resfile.write(ip)


def AnalyzeConfigurations(data, scandir, ip):
    global configurations
    ###  Configuration Check
    for config in configurations.keys():
        if re.search(str(base64.b64decode((configurations[config])[1]),'utf-8')  , data):
            writeResult("{}/Configurations/{}".format(scandir,(configurations[config])[0]),ip)


def AnalyzeProtocols(data, scandir, ip):
    global protocols
    ###  Weak protocols Check
    for proto in protocols.keys():
        if re.search(str(base64.b64decode((protocols[proto])[1]),'utf-8')  , data):
            writeResult("{}/Protocols/{}".format(scandir,(protocols[proto])[0]),ip)


def AnalyzeFlaws(data, scandir, ip):
    global flaws
    ###  Flaws Check
    for flaw in flaws.keys():
        if re.search(str(base64.b64decode((flaws[flaw])[1]),'utf-8')  , data):
            writeResult("{}/Flaws/{}".format(scandir,(flaws[flaw])[0]),ip)

def AnalyzeCiphers(data, scandir, ip):
    global ciphers
    ###  Cipher algorithms Check
    for cipher in ciphers.keys():
        if re.search(str(base64.b64decode((ciphers[cipher])[1]),'utf-8')  , data):
            writeResult("{}/CipherSuites/{}".format(scandir,(ciphers[cipher])[0]),ip)


def AnalyzeCertificates(data, scandir, ip):
    global certificates
    ###  Certificates Check
    try:
        Days = int((re.findall('Certificate Validity \(UTC\) +(?:(\d+)|expired)', data))[0])
        if(Days > 1186):
            writeResult("{}/Certificates/{}".format(scandir,'TooLongCetificateValidity.txt'),ip)
    except:
        pass
    Issuer = (re.findall('Issuer +(.+)', data))[0]
    writeResult("{}/Certificates/{}".format(scandir,'Issuer.txt'),"{}\t\t\t{}\n".format(ip[:-1], Issuer))

    for certificate in certificates.keys():
        if re.search(str(base64.b64decode((certificates[certificate])[1]),'utf-8')  , data):
            writeResult("{}/Certificates/{}".format(scandir,(certificates[certificate])[0]),ip)


def createDirectories(scandir):
    DirNames = ["Protocols","CipherSuites","Flaws","Certificates","Configurations"]
    for Dir in DirNames:
        if(os.path.isdir("{}/{}".format(scandir,Dir)) == False):
            os.mkdir("{}/{}".format(scandir,Dir))

def AnalyzeScanFile(scandir, iplist):
    cprint("[-] Starting analyzing testssl.sh result files", 'blue')
    createDirectories(scandir)
    with open(iplist, 'r') as f:
        for ip in f:
            with open("{}/{}.txt".format(scandir,ip[:-1]), 'r') as scan:
                data = scan.read()
                  
                AnalyzeProtocols(data, scandir, ip)
                AnalyzeFlaws(data, scandir, ip)
                AnalyzeCiphers(data, scandir, ip)
                AnalyzeCertificates(data, scandir, ip)
                AnalyzeConfigurations(data, scandir, ip)
    cprint("[+] Analyze done", 'blue')
    print()
    cprint("[+] All result can be found in {}".format(scandir), 'white')


def  configProtocols():
    global protocols
    with open('config/protocols.csv', 'r') as f:
        for line in f:
            elems = (line[:-1]).split(',')
            protocols[elems[0]] = [elems[1] , elems[2]]

def  configFlaws():
    global flaws
    with open('config/flaws.csv', 'r') as f:
        for line in f:
            elems = (line[:-1]).split(',')
            flaws[elems[0]] = [elems[1] , elems[2]]

def  configCiphers():
    global ciphers
    with open('config/ciphers.csv', 'r') as f:
        for line in f:
            elems = (line[:-1]).split(',')
            ciphers[elems[0]] = [elems[1] , elems[2]]


def  configCertificates():
    global certificates
    with open('config/certificates.csv', 'r') as f:
        for line in f:
            elems = (line[:-1]).split(',')
            certificates[elems[0]] = [elems[1] , elems[2]]

def configConfigurations():
    global configurations
    with open('config/configurations.csv', 'r') as f:
        for line in f:
            elems = (line[:-1]).split(',')
            configurations[elems[0]] = [elems[1] , elems[2]]

def printStartMessage():
    cprint("#####################", 'white')
    cprint("#                   #", 'white')
    cprint("# I Don't Speak SSL #", 'white')
    cprint("#                   #", 'white')
    cprint("#####################", 'white')
    print()
    cprint("It's a script made to parse testssl.sh results", 'white')
    cprint("and higlthed the important findings that need to be reported", 'white')
    cprint("Developed to work with testssl 2.9dev", 'white')
    print()

def config():
    cprint("[-] Loading configuration files", 'blue')
    configProtocols()
    configFlaws()
    configCiphers()
    configCertificates() 
    configConfigurations()
    cprint("[+] Done", 'green')
    print()


def main(scandir, iplist, testssl):
    printStartMessage()
    config()
    try:
        scan(scandir, iplist, testssl)
        AnalyzeScanFile(scandir, iplist)
    except KeyboardInterrupt:
        cprint("Killing script", 'red')
        sys.exit(0)



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Run test SSL on a IP list')

    parser.add_argument('-d', action="store", help="Scans destination directory" , dest="dir", type=str)
    parser.add_argument('-l', action="store", help="File containing taget ips or domain names list, one per line", dest="iplist", type=str)
    parser.add_argument('-t', action="store", help="testssl.sh script location", dest="testssl", type=str)
    args = parser.parse_args()
    if(args.dir and args.iplist and args.testssl):
        main(args.dir, args.iplist, args.testssl)
    else:
        parser.print_help(sys.stderr)
