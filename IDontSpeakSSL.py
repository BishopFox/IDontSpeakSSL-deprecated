#!/usr/bin/env python3

import os,  mmap, argparse, re, base64, sys, socket, ssl, shutil, time
from termcolor import colored, cprint
from os import listdir
from os.path import isfile, join
from yattag import Doc, indent
from queue import Queue
from threading import Thread

findingConfig = {}

class Report:

    def __init__(self,scanDir,iplist):
        self.reportDir=scanDir
        self.iplist=iplist
        self.doc = Doc()
        self.tag = self.doc.tag
        self.line = self.doc.line
        self.stag = self.doc.stag
        self.text = self.doc.text



    def createReport(self):
        print()
        cprint("[-] Starting the generation of the report", 'blue')
        self.copyJSCSS()
        self.doc.asis('<!DOCTYPE html>')
        with self.tag('html'):
            self.createHead()
            self.createBody()
        self.writeReport()
        cprint("[+] Report generated", 'green')
        cprint("[+] All results could be found in {}/report.html".format(self.reportDir), 'green')

    def copyJSCSS(self):
        if(os.path.isdir("{}/html".format(self.reportDir)) == False):
            shutil.copytree('resources', "{}/html".format(self.reportDir))



    def createHead(self):
        with self.tag('head'):
            self.line('title', 'IDontSpeakSSL Report')
            self.stag('link', ("rel", "stylesheet"), ("href", "./html/css/bootstrap.min.css".format(self.reportDir)) )
            self.line('script', '', src="./html/js/jquery.min.js".format(self.reportDir))
            self.line('script', '', src="./html/js/bootstrap.min.js".format(self.reportDir))
            

    def addScope(self):
        with self.tag('ul'):
            with open(self.iplist, 'r') as f:
                for ip in f:
                    ip=ip.strip()
                    self.line('li', ip)

    def createBody(self):
        with self.tag('body'):
            with self.tag('div'):
                self.doc.attr(klass='container')
                self.line('h1', 'IDontSpeakSSL Report') 
                with self.tag('p'):
                    self.text('Report of IDontSpeakSSL script, All findings are split into sections.')
                    self.stag('br')
                    self.text('The scope given to the script was:')
                    self.addScope()


                self.addSection("Certificate Findings", "Certificates" ,"Certificates", "Finding DB: Insecure SSL/TLS Certificate Configuration")
                self.addSection("Weak Cipher Suites", "CipherSuites" ,"Ciphers", "Fiding DB - Weak Cryptography")
                self.addSection("Weak Protocols", "Protocols" ,"Protocols", "Fiding DB - Insecure Network Transmission")
                self.addSection("Bad Configurations", "Configurations" ,"Configurations", "Fiding DB - Missing Security Headers")
                self.addSection("Known Vulnerabilities", "Flaws" ,"Flaws", "Fiding DB - Insecure Network Transmission or Weak Cryptography")


    def listAssets(self, folder, assetfile):
        if(os.path.exists( "{}/{}/{}".format(self.reportDir, folder, assetfile))):
            with self.tag('ul'):
                with open("{}/{}/{}".format(self.reportDir, folder, assetfile), 'r') as assets:
                    for asset in assets:
                        self.line('li', asset )

        else:
            self.text("No affected location for this finding.")


    def addSection(self, SectionName, folder, findingType, findingDBRef):
        global findingConfig
        self.line('h2', SectionName)
        self.line('p', findingDBRef)
        with self.tag('div'):
            self.doc.attr(klass='panel-group')
            findingid=0
            for finding in (findingConfig[findingType]).keys():
                if(os.path.exists( "{}/{}/{}".format(self.reportDir, folder,(findingConfig[findingType])[finding][0]))):
                    with self.tag('div', klass='panel panel-default'):                                                                                                   
                        with self.tag('div', klass='panel-heading'):
                            with self.tag('div', klass='panel-title'):
                                with self.tag('h4', klass='panel-title'):
                                    with self.tag('a', ("data-toggle", "collapse"), ("href" ,"#{}{}".format(findingType,findingid))):
                                        self.text("{}".format((findingConfig[findingType])[finding][2]))
                        with self.tag('div'):                                                                 
                            self.doc.attr(klass='panel-collapse collapse', id='{}{}'.format(findingType,findingid))    
                            with self.tag('div', klass='panel-body'):                                            
                                self.text("{}".format((findingConfig[findingType])[finding][3]))
                                self.listAssets(folder, (findingConfig[findingType])[finding][0])
                    findingid+=1
            if(findingType=="Certificates"):
                if(os.path.exists( "{}/{}/{}".format(self.reportDir, folder,"TooLongCetificateValidity.txt"))):
                    self.addCertificateValidity(findingType,findingid, folder)
                    findingid+=1
                if(os.path.exists( "{}/{}/{}".format(self.reportDir, folder,"Issuers.txt"))):
                    self.addCertificateIssuers(findingType,findingid, folder)
    
    def addCertificateValidity(self, findingType, findingid, folder):
        with self.tag('div', klass='panel panel-default'):                                                                                               
            with self.tag('div', klass='panel-heading'):
                with self.tag('div', klass='panel-title'):
                    with self.tag('h4', klass='panel-title'):
                        with self.tag('a', ("data-toggle", "collapse"), ("href" ,"#{}{}".format(findingType,findingid))):
                            self.text("{}".format("Certificate With Too Long Validity Period"))
            with self.tag('div'):                                                                 
                self.doc.attr(klass='panel-collapse collapse', id='{}{}'.format(findingType,findingid))    
                with self.tag('div', klass='panel-body'):                                            
                    self.text("{}".format("Certificate validity period must be limited to 39 months for certificates issued before March 1st, 2018, or 825 days for certificates issued after March 1st, 2018.<br>(https://www.globalsign.com/en/blog/ssl-certificate-validity-capped-at-maximum-two-years/)<br>(https://www.symantec.com/connect/blogs/new-39-month-ssl-certificate-maximum-validity)"))
                    self.listAssets(folder,"TooLongCetificateValidity.txt")



    def addCertificateIssuers(self, findingType, findingid, folder):
        with self.tag('div', klass='panel panel-default'):                                                                                               
            with self.tag('div', klass='panel-heading'):
                with self.tag('div', klass='panel-title'):
                    with self.tag('h4', klass='panel-title'):
                        with self.tag('a', ("data-toggle", "collapse"), ("href" ,"#{}{}".format(findingType,findingid))):
                            self.text("{}".format("Certificate Issuers"))
            with self.tag('div'):                                                                 
                self.doc.attr(klass='panel-collapse collapse', id='{}{}'.format(findingType,findingid))    
                with self.tag('div', klass='panel-body'):                                            
                    self.text("{}".format("Certificates Issuers must be check, all certificates must be issued by a trusted Certificate Authority. The CA could be a knon certificate authorithy such as Symentec, Verisign, etc. or an internal CA. The script is not able to check the CA, you should verified by yourself the issuer."))
                    self.listAssets(folder,"Issuers.txt" )



    def writeReport(self):
        with open("{}/report.html".format(self.reportDir), 'w') as report:
            report.write(indent(self.doc.getvalue()))



def scanTarget(queue):
    ip, testssl, scandir = queue.get()
    if((testConnection(ip))==0):
        cprint("[-] Scanning {}".format(ip), 'blue')
        os.system("{} --color 0 {} > {}/TestSSLscans/{}.txt".format(testssl, ip, scandir, ip))  
        cprint("[+] {} scan done".format(ip), 'green')
    queue.task_done()

def scan(scandir, iplist, testssl, nbWorker=8):
    queue = Queue()
    for x in range(nbWorker):
        worker = Thread(target=scanTarget, args=(queue,))
        worker.setDaemon(True)
        worker.start()
    with open(iplist, 'r') as f:
        for ip in f:
            ip=ip.strip()
            if ip!="":
                queue.put((ip, testssl, scandir))
    queue.join()


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

def analyze(findingType, folder, data, scandir, ip):
    global findingConfig
    for finding in (findingConfig[findingType]).keys():
        if re.search(str(base64.b64decode(((findingConfig[findingType])[finding])[1]),'utf-8')  , data):
            writeResult("{}/{}/{}".format(scandir,folder,((findingConfig[findingType])[finding])[0],folder),"{}\n".format(ip))

def AnalyzeCertificates(folder, data, scandir, ip):
    ###  Certificates Check
    try:
        Days = int((re.findall('Certificate Validity \(UTC\) +(?:(\d+)|expired)', data))[0])
        if(Days > 825):
            writeResult("{}/{}/{}".format(scandir,folder,'TooLongCetificateValidity.txt'),"{}\t{} days\n".format(ip,Days))
    except:
        pass
    Issuer = (re.findall('Issuer +(.+)', data))[0]
    writeResult("{}/{}/{}".format(scandir,folder,'Issuers.txt'),"{}\t\t\t{}\n".format(ip.strip(), Issuer))


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
                analyze('Protocols', 'Protocols', data, scandir, scanFile[:-4])
                analyze('Ciphers', 'CipherSuites', data, scandir, scanFile[:-4])
                analyze('Flaws', 'Flaws', data, scandir, scanFile[:-4])
                analyze('Certificates', 'Certificates', data, scandir, scanFile[:-4])
                analyze('Configurations', 'Configurations', data, scandir, scanFile[:-4])
                AnalyzeCertificates('Certificates',data, scandir, scanFile[:-4])
    cprint("[+] Analyze done", 'blue')
    print()


def doConfig():
    global findingConfig
    cprint("[-] Loading Certificate findings", 'blue')
    findingConfig['Certificates'] = getConfigFromFile('config/certificates.csv')
    cprint("[-] Loading Protocol findings", 'blue')
    findingConfig['Protocols'] = getConfigFromFile('config/protocols.csv')
    cprint("[-] Loading Flaw findings", 'blue')
    findingConfig['Flaws'] = getConfigFromFile('config/flaws.csv')
    cprint("[-] Loading Cipher findings", 'blue')
    findingConfig['Ciphers'] = getConfigFromFile('config/ciphers.csv')
    cprint("[-] Loading Configuration findings", 'blue')
    findingConfig['Configurations'] = getConfigFromFile('config/configurations.csv')

def getConfigFromFile(configfile):
    findingConfig = {}
    with open(configfile, 'r') as f:
        for line in f:
            elems = (line.strip()).split(',')
            findingConfig[elems[0]] = [elems[1] , elems[2], elems[3], elems[4]] 
    return findingConfig

def printStartMessage():
    cprint("#####################", 'white')
    cprint("#                   #", 'white')
    cprint("# I Don't Speak SSL #", 'white')
    cprint("#                   #", 'white')
    cprint("#####################", 'white')
    print()
    cprint("It's a script made to parse testssl.sh results", 'white')
    cprint("and highlight the important findings that need to be reported", 'white')
    cprint("Developed to work with testssl 2.9dev", 'white')
    print()

def config():
    cprint("[-] Loading configuration files", 'blue')
    doConfig()
    cprint("[+] Done", 'green')
    print()


def main(scandir, iplist, testssl, nbWorker):
    printStartMessage()
    config()
    createDirectories(scandir)
    scan(scandir, iplist, testssl, nbWorker)
    AnalyzeScanFile(scandir, iplist)
    report = Report(scandir, iplist)
    report.createReport()

def checkArgd(argd):
    if argd:
        if argd != "":
            if(os.path.isdir("{}".format(argd)) == False):
                os.mkdir("{}".format(argd))
            return argd
    path = os.path.abspath(os.path.dirname(sys.argv[0]))
    while True:
        nameDir = "{}_results".format(time.strftime("%Y%m%d%I%M%S%p"))
        if(os.path.isdir("{}/{}".format(path,nameDir)) == False):
            os.mkdir("{}/{}".format(path, nameDir))
            break
    return "{}/{}".format(path, nameDir)


def checkTargets(targetFile, targetList, scanDir):
    if ( not (targetFile or targetList)):
        return False
    if(targetFile):
        if(targetList):
            shutil.copyfile(targetFile, "{}/scope.txt".format(scanDir))
        else:
            if(os.path.exists(targetFile)):
                shutil.copyfile(targetFile, "{}/scope.txt".format(scanDir))
                return "{}/scope.txt".format(scanDir)
            else:
                cprint("[-] Target file doesn't exist", 'red')
                return False
    with open("{}/scope.txt".format(scanDir), "a") as targets:
        for target in targetList:
            targets.write("{}\n".format(target))
    return "{}/scope.txt".format(scanDir)

def checkTestSSL(testSSL):
    if testSSL:
        if(os.path.exists(testSSL)):
            return testSSL
        else:
            cprint("[-] Given path for testssl.sh script is incorrect", 'red')
            exit()
    else:
        return "{}/testssl.sh/testssl.sh".format(os.path.abspath(os.path.dirname(sys.argv[0])))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Run test SSL on a IP list')

    parser.add_argument('-d', action="store", help="Scans destination directory" , dest="dir", type=str)
    parser.add_argument('-f', action="store", help="File containing taget IPs or domain names list, one per line", dest="targetFile", type=str)
    parser.add_argument('-i', action="store", nargs='+', help="List of taget IPs or domain names, separeted by a space", dest="targetList", type=str)
    parser.add_argument('-t', action="store", help="testssl.sh script location", dest="testssl", type=str)
    parser.add_argument('-w', action="store", help="number of workers. Number of scan to run at the same time. By default defined to 8", dest="nbWorker", type=int, default=8)
    args = parser.parse_args()
    print(args)
    if ((args.targetFile or args.targetList)):
        scanDir = checkArgd(args.dir)
        targetFile = checkTargets(args.targetFile, args.targetList, scanDir)
        if(targetFile):
            testSSL = checkTestSSL(args.testssl)
            main(scanDir, targetFile, testSSL,args.nbWorker)
        else:
            parser.print_help(sys.stderr)
    else:
        parser.print_help(sys.stderr)
