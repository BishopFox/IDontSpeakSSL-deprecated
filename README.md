# IDontSpeakSSL

IDontSpeakSSL is a simple script to parse testssl.sh results. It is designed to automate the discovery of bad practices for SSL/TLS configurations, cipher suites, and certificates.
It is useful on a large scope, for example during internal penetration testing or external testing on a large scope.

For more information on testssl.sh, see [testssl.sh](https://testssl.sh/).


![Usage Example](https://raw.githubusercontent.com/BishopFox/IDontSpeakSSL/master/img/exec.png)


## Download the Script

The testssl.sh script is embedded as a submodule. In order to properly download the IDontSpeakSSL script, use the following git commands:

```
git clone https://github.com/BishopFox/IDontSpeakSSL.git --recursive
```
or
```
git clone https://github.com/BishopFox/IDontSpeakSSL.git
git submodule update --init --recursive
```

## Install Requirements

To fetch the necessary libraries, use the following command:

```
pip3 install -r requirements.txt
```

## Usage

This script accepts the following options:
* `-t` Path to a specific testssl.sh script (optional)
* `-f` Path to a file containing the list of IP addresses or domain names to scan
* `-i` List of IP addresses or domain names to scan
* `-d` Path to the directory where all results of the scans and analyses will be saved
* `-w` Number of workers to perform the scans (By default defined to 8)

To run properly, either `-i` or `-f` (or both) is required.
Here are some examples of how to use IDontSpeakSSL:

```
python3 IDontSpeakSSL.py -f scope.txt
python3 IDontSpeakSSL.py -i www.google.com,www.facebook.com,10.0.0.1
python3 IDontSpeakSSL.py -f scope.txt -i www.facebook.com,10.0.0.1
python3 IDontSpeakSSL.py -f scope.txt -d result/directory
python3 IDontSpeakSSL.py -f scope.txt -d result/directory -w 16
python3 IDontSpeakSSL.py -t /path/to/testssl/script/testssl.sh -l scope.txt -d result/directory
```

## IPs and Domain Names List

As a parameter, IDontSpeakSSL requires sending a flat file containing a list of services to scan. This list must be set according to the following syntax:

```
10.0.0.1
10.0.0.2
10.0.0.3:8443
www.example.com
www.example.com:8000
```

If a port other than 443 should be scanned, the port number must be added after the IP address or the domain name, separated with a colon.
No URL should be set with a scheme. For example, `https://www.example.com` will produce an error.

## Configuration Files

This script will read configuration files located in the `config` folder. The configuration files follow the CSV format. Each line of this configuration file is split into five columns and organized as follows:

| Name of the test | Output file of the test | Regular expression Base64-encoded  | Title of the finding | Description of the finding |


## Example Report

Here is an example of a report made by IDontSpeakSSL:

![Report](https://raw.githubusercontent.com/BishopFox/IDontSpeakSSL/master/img/report.png)

## Maintainer

trivette - Florian Nivette <fnivette@bishopfox.com>
