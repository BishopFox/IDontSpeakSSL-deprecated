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

    def __init__(self,scanDir, targetlist):
        self.reportDir=scanDir
        self.targetlist=targetlist
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
            for target in self.targetlist:
                self.line('li', ":".join(target))

    def createBody(self):
        with self.tag('body'):
            with self.tag('div'):
                self.doc.attr(klass='container')
                self.line('h1', 'IDontSpeakSSL Report') 
                with self.tag('p'):
                    self.text('Report of IDontSpeakSSL script, all findings are splitted into sections.')
                    self.stag('br')
                    self.text('The scope was:')
                    self.addScope()


                self.addSection("Certificate Findings", "Certificates" ,"Certificates", "Insecure SSL/TLS Certificate Configuration")
                self.addSection("Weak Cipher Suites", "CipherSuites" ,"Ciphers", "Weak Crypto suites")
                self.addSection("Weak Protocols", "Protocols" ,"Protocols", "Insecure Network Transmission")
                self.addSection("Bad Configurations", "Configurations" ,"Configurations", "Missing Security Headers")
                self.addSection("Known Vulnerabilities", "Flaws" ,"Flaws", "Insecure Network Transmission or Weak Cryptography")


    def listAssets(self, folder, assetfile):
        if(os.path.exists( "{}/{}/{}".format(self.reportDir, folder, assetfile))):
            with self.tag('ul'):
                with open("{}/{}/{}".format(self.reportDir, folder, assetfile), 'r') as assets:
                    for asset in assets:
                        self.line('li', asset )

        else:
            self.text("No affected location for this finding.")


    def addSection(self, SectionName, folder, findingType, findingDBRef):
        if(len(listdir("{}/{}".format(self.reportDir,folder)))<1):
            return
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
                    self.text("{}".format("Certificate Issuers must be check from your end, all certificates must be issued by a trusted Certificate Authority. The CA could be a publicly known certificate authorithy such as Symantec, Verisign, etc. or an internal CA."))
                    self.listAssets(folder,"Issuers.txt" )



    def writeReport(self):
        with open("{}/report.html".format(self.reportDir), 'w') as report:
            report.write(indent(self.doc.getvalue()))



def scanTarget(queue):
    while(not queue.empty()):
        target, testssl, scandir, targetid, targetnb = queue.get()
        cprint("[-] {}/{} Scanning {}".format(targetid, targetnb, target), 'blue')
        os.system("{} --color 0 {} > {}/TestSSLscans/{}.txt".format(testssl, target, scandir, target))
        cprint("[+] {}/{} {} scan done".format(targetid, targetnb, target), 'green')
        queue.task_done()
    return

def scan(scandir, targetlist, testssl, nbWorker=8):
    queue = Queue()
    #ipnb = sum(1 for line in open(iplist))
    targetnb = len(targetlist)-1
    i=0
    for target in targetlist:
        queue.put((":".join(target), testssl, scandir, i, targetnb))
        i+=1
    for x in range(nbWorker):
        worker = Thread(target=scanTarget, args=(queue,))
        worker.setDaemon(True)
        worker.start()
    queue.join()
    return


"""
Test if the remote server port is open and using SSL/TLS. 
The function will return:
0 if everything is good
1 if something is wrong
"""
def sslConnect(server, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    wrappedSocket = ssl.wrap_socket(sock)
    try:
        wrappedSocket.connect((server,port))
    except (ssl.SSLError, socket.timeout, ConnectionRefusedError, ConnectionResetError, OSError) as err:
        if str(err) == "timed out":
            cprint("[i] {}:{} Port not open, timed out".format(server, port), 'red')
            sock.close()
            return 0
        if re.compile("WRONG_VERSION_NUMBER").search(str(err),1):
            cprint("[i] {}:{} Remote server doesn't offer SSL/TLS connection".format(server, port), 'red')
            sock.close()
            return 0
        if re.compile("Connection refused").search(str(err),1):
            cprint("[i] {}:{} Connection refused by remote server".format(server, port), 'red')
            sock.close()
            return 0
        if re.compile("Connection reset by peer").search(str(err),1):
            cprint("[i] {}:{} Connection reset".format(server, port), 'red')
            sock.close()
            return 0
        if re.compile("The handshake operation timed out").search(str(err),1):
            cprint("[i] {}:{} Not a valid SSL/TLS server".format(server, port), 'red')
            sock.close()
            return 0
        if re.compile("DH_KEY_TOO_SMALL").search(str(err),1):
            #cprint("[i] {}:{} DH key too small, but Testssl can do it".format(server, port), 'yellow')
            pass
        if re.compile("Errno 0").search(str(err),1):
            #cprint("[i] {}:{} Old cipher suite not supported by your OS, TestSSL can handle it but if it continiue to fail remove the IP".format(server, port), 'yellow')
            pass
        if re.compile("SSLV3_ALERT_HANDSHAKE_FAILURE").search(str(err),1):
            #cprint("[i] {}:{} Handshake failure, but Testssl can do it".format(server, port), 'yellow')
            pass
    sock.close()

    return 1


"""
Verify domain name
0 invalid domain name, no resolution
1 valid domain name
"""
def testDomainName(target):
    try:
        socket.gethostbyname(target)
    except:
        cprint("[+] {} domain name unresolved".format(target), 'red')
        return 0
    return 1


"""
Verify if the remote server porti is open, domain name is valid and if 
it's offering SSL/TLS:
0 something is wrong
1 everything is good
"""
def testConnection(target):
    if(not(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",target[0]))):
        if testDomainName(target[0]):
            return sslConnect(target[0],int(target[1]))
        else:
            return 0
    return sslConnect(target[0],int(target[1]))
    
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
    if(len(re.findall('Issuer +(.+)', data))>0):
        Issuer = (re.findall('Issuer +(.+)', data))[0]
        writeResult("{}/{}/{}".format(scandir,folder,'Issuers.txt'),"{}\t\t\t{}\n".format(ip.strip(), Issuer))


def createDirectories(scandir):
    DirNames = ["Protocols","CipherSuites","Flaws","Certificates","Configurations", "TestSSLscans"]
    for Dir in DirNames:
        if(os.path.isdir("{}/{}".format(scandir,Dir)) == False):
            os.mkdir("{}/{}".format(scandir,Dir))

def AnalyzeScanFile(scandir):
    print()
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


def doConfig():
    global findingConfig
    cprint("\n[-] Loading Certificate findings", 'blue')
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
    cprint("IDontSpeakSSL is a simple script to parse testssl.sh results", 'white')
    cprint("and highlight important findings that need to be reported.", 'white')
    cprint("Developed to work with testssl 2.9dev", 'white')
    print()

def config():
    cprint("[-] Loading all configuration files", 'blue')
    doConfig()
    cprint("[+] Done", 'green')
    print()

def prepareTargetList(path, iplist):
    print(iplist)

    targetlist=[]
    i=0
    j=0
    cprint("Reviewing target list", 'blue')
    with open(path,'r') as targetfile:
        for target in targetfile:
            target =target.strip()
            if target !="":
                t = target.split(":")
                if len(t)==1:
                    t.append("443")
                if(testConnection(t)):
                    
                    targetlist.append(t)
                i+=1
    if iplist!=None:
        for target in iplist[0].split(","):
            if target !="":
                t = target.split(":")    
                if len(t)==1:
                    t.append("443")
                if(testConnection(t)):
                    
                    targetlist.append(t)
                j+=1

    cprint("Target list reduced to {} out of {}".format(len(targetlist),i+j), 'blue')
    return targetlist

def run(scandir, ipfile, iplist, testssl, nbWorker):
    printStartMessage()
    config()
    targetlist = prepareTargetList(ipfile, iplist)
    createDirectories(scandir)
    scan(scandir, targetlist, testssl, nbWorker)
    AnalyzeScanFile(scandir)
    report = Report(scandir, targetlist)
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

def clearAnalyzeFolder(path):
    clearFolder("{}/Certificates/".format(path))
    clearFolder("{}/CipherSuites/".format(path))
    clearFolder("{}/Configurations/".format(path))
    clearFolder("{}/Flaws/".format(path))
    clearFolder("{}/Protocols/".format(path))

def generateReportFromScan(path):
    # Implement checks on file exist and might need to remove the generated
    targetlist = generateList("{}/scope.txt".format(path))
    config()
    clearAnalyzeFolder(path)
    AnalyzeScanFile(path)
    report = Report(path, targetlist)
    report.createReport()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Run test SSL on a IP list')

    parser.add_argument('-d', action="store", help="Scans destination directory" , dest="dir", type=str)
    parser.add_argument('-f', action="store", help="File containing taget IPs or domain names list, one per line", dest="targetFile", type=str)
    parser.add_argument('-i', action="store", nargs='+', help="List of taget IPs or domain names, separeted by a coma", dest="targetList", type=str)
    parser.add_argument('-t', action="store", help="testssl.sh script location", dest="testssl", type=str)
    parser.add_argument('-w', action="store", help="number of workers. Number of scan to run at the same time. By default defined to 8", dest="nbWorker", type=int, default=8)
    parser.add_argument('-r', action="store", help="Generate a report from scan files. Take a path to the scan folder.", dest="report", type=str)
    args = parser.parse_args()
    if (args.report):
        generateReportFromScan(args.report)
    else:
        if ((args.targetFile or args.targetList)):                               
            scanDir = checkArgd(args.dir)
            targetFile = checkTargets(args.targetFile, args.targetList, scanDir)
            if(targetFile):
                testSSL = checkTestSSL(args.testssl)
                run(scanDir, targetFile, args.targetList, testSSL,args.nbWorker)
            else:
                parser.print_help(sys.stderr)
        else:
            parser.print_help(sys.stderr)
