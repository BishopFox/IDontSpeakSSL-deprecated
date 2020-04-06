from yattag import Doc, indent

class IDontSpeakSSLReport:

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
