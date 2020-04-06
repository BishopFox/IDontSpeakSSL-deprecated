from idontspeakssl.common.constant import TESTSSL_BASE_URL, IDONTSPEAKSSL_VERSION_URL, TESTSSLSH_VERSION_URL
from idontspeakssl.common.printer import print_green, print_red
import idontspeakssl, tarfile
import os, re, requests, pkg_resources

def get_testssl_version(testssl_path):
    testssl_script_file = open(testssl_path, "r")
    compiled_sequence = re.compile(r"declare -r VERSION=\"([0-9\.\-rc]+)\"",re.MULTILINE)
    version = compiled_sequence.findall(testssl_script_file.read())
    if(len(version) == 1):
        return version[0]
    else:
        return "0"  

def check_testssl_version(testssl_path):
    if(testssl_path == None):
        testssl_path = os.path.join(os.path.dirname(idontspeakssl.__file__),"lib","testssl.sh/testssl.sh")
    latest_testsslsh_version = (requests.get(TESTSSLSH_VERSION_URL)).text
    if(os.path.isfile(testssl_path)):
        if latest_testsslsh_version == get_testssl_version(testssl_path):
            print_green("[i] testssl.sh is up-to-date")
        else:
            print_red("[!] testssl.sh is not up-to-date. The version {} of testssl.sh is needed.")
            ask_for_update(latest_testsslsh_version)
            
    else:
        print_red("[!] testssl.sh not found.")
        ask_for_download(latest_testsslsh_version)
    return testssl_path

# the two next methods can be done in one #TODO
def ask_for_update(version):
        choice = click.prompt(
            """[-] Do you want to proceed with the update,
(y) Yes, do the update.,
(n) No, don't do the update.""",
            type=click.Choice(['y', 'n']),
            default="y",
            )
        if choice == "y":
            download_testssl(latest_testsslsh_version)
        else:
            print_red("Please download a version of testssl.sh version {} to use properly idontspeakssl." % latest_testsslsh_version)
            exit()

def ask_for_download(version):
    choice = click.prompt(
    """[-] Do you want to procedd with the download?
(y) Yes, download testssl.sh.,
(n) No, don't download testssl.sh.""",
    type=click.Choice(['y', 'n']),
    default="y",
    )
    if choice == "y":
        download_testssl(latest_testsslsh_version)
    else:
        print_red("Please download a version of testssl.sh version {} to use properly idontspeakssl." % latest_testsslsh_version)
        exit()

def check_idonspeakssl_version():
    latest_idontspeakssl_version = (requests.get(IDONTSPEAKSSL_VERSION_URL)).text
    if pkg_resources.get_distribution("idontspeakssl").version ==  latest_idontspeakssl_version:
        print_green("[i] idontspeakssl is up-to-date.")
    else:
        print_red("[!] idontspeakssl is not up-to-date.")


def untar(file_path, lib_path):
    tar = tarfile.open(file_path)
    tar.extractall(path=lib_path)
    tar.close()

def download_testssl(version):
    lib_path = os.path.join(os.path.dirname(idontspeakssl.__file__),"lib")
    if os.path.exists(os.path.join(lib_path,"testssl.sh")):
        os.remove(os.path.join(lib_path,"testssl.sh"))
    r = requests.get("{}{}.tar.gz".format(TESTSSL_BASE_URL,version))
    with open(os.path.join(lib_path, "testssl.tar.gz"), 'wb') as f:
        f.write(r.content)
        untar(os.path.join(lib_path,"testssl.tar.gz"), lib_path)
        os.rename(os.path.join(lib_path, "testssl.sh-{}".format(version)),os.path.join(lib_path, "testssl.sh"))
        os.remove(os.path.join(lib_path, "testssl.tar.gz"))