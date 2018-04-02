#!/usr/bin/env python3

import os,  mmap, argparse, re, base64, sys, socket, ssl
from termcolor import colored, cprint
from os import listdir
from os.path import isfile, join


protocols = {}
flaws = {}
ciphers = {}
certificates = {}
configurations = {}


def scan(scandir, iplist, testssl):
    with open(iplist, 'r') as f:
            for ip in f:
                if ip[-1]=="\n":
                    ip=ip[:-1]
                if((testConnection(ip))==0):
                    cprint("[-] Scanning {}".format(ip), 'blue')
                    os.system("{} --color 0 {} > {}/TestSSLscans/{}.txt".format(testssl, ip, scandir, ip))  
                    cprint("[+] {} scan done".format(ip), 'green')


"""
The function is here to test if the remote server got is port open, the domain name is valid and if 
it's offering SSL/TLS. The dunction will return:
0 if everything is good
1 if the port is not open
2 if ssl is not offered
"""
def sslConnect(server, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    wrappedSocket = ssl.wrap_socket(sock)
    try:
        wrappedSocket.connect((server,port))
    except (ssl.SSLError, socket.timeout, ConnectionRefusedError) as err:
        if str(err) == "timed out":
            cprint("[+] {} Port not open, timed out".format(server, port), 'red')
            sock.close()
            return 1
        if re.compile("WRONG_VERSION_NUMBER").search(str(err),1):
            cprint("[+] {}:{} Remote server doesn't offer SSL/TLS connection".format(server, port), 'red')
            sock.close()
            return 2
        if re.compile("Connection refused").search(str(err),1):
            cprint("[+] {}:{} Connection refused by remote server".format(server, port), 'red')
            sock.close()
            return 1
    sock.close()
    return 0



"""
The function is here to test if the remote server got is port open, the domain name is valid and if 
it's offering SSL/TLS. The dunction will return:
0 if everything is good
1 if the port is not open
2 if ssl is not offered
3 if the domain name is invalid
"""
def testConnection(IP):
    serverInfo = IP.split(':')
    if(not(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",serverInfo[0]))):
        try:
            if (len(socket.gethostbyname(serverInfo[0]))<1):
                cprint("[-] {} is a valid domain name".format(serverInfo[0]), 'blue')
        except:
            cprint("[+] {} domain name unresolved".format(serverInfo[0]), 'red')
            return 3
    if(len(serverInfo)>1):
        return sslConnect(serverInfo[0],int(serverInfo[1]))
    else:
        return sslConnect(serverInfo[0],443)




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
    DirNames = ["Protocols","CipherSuites","Flaws","Certificates","Configurations", "TestSSLscans"]
    for Dir in DirNames:
        if(os.path.isdir("{}/{}".format(scandir,Dir)) == False):
            os.mkdir("{}/{}".format(scandir,Dir))

def AnalyzeScanFile(scandir, iplist):
    cprint("[-] Starting analyzing testssl.sh result files", 'blue')
    scanFiles = [f for f in listdir("{}/TestSSLscans".format(scandir)) if isfile(join("{}/TestSSLscans".format(scandir), f))]
    for scanFile in scanFiles:
            with open("{}/TestSSLscans/{}".format(scandir,scanFile), 'r') as scan:
                data = scan.read()
                # the scanFile[:-4] to remove the .txt
                AnalyzeProtocols(data, scandir, scanFile[:-4])
                AnalyzeFlaws(data, scandir, scanFile[:-4])
                AnalyzeCiphers(data, scandir, scanFile[:-4])
                AnalyzeCertificates(data, scandir, scanFile[:-4])
                AnalyzeConfigurations(data, scandir, scanFile[:-4])
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
    createDirectories(scandir)
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
