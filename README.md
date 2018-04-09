# IDontSpeakSSL

IDontSpeakSSL is a simple script to made parse testssl.sh results. It's purpose is to automate the discovery of bad practices on SSL/TLS confiuration, Cipher suites and Certificates.
It is useful on large scope, for example during internal or large external penetration testing.

For more information on testssl.sh see [testssl.sh](https://testssl.sh/).

**IT'S A PYTHON 3 SCRIPT**

## Download the script

The testssl.sh script is embedded as a submodule. In order to properly get IDontSpeakSSL script use the following git commands:

```
git clone https://github.com/BishopFox/IDontSpeakSSL.git --recursive
```
or
```
git clone https://github.com/BishopFox/IDontSpeakSSL.git
git submodule update --init --recursive
```

## install requirements


To fetch the needed libraries, use the follwoing command:

```
pip3 -r requirements.txt
```


## Usage

This script accept the following options:
* -t a path to a specific testssl.sh script (optional)
* -f a path to file containing the list of IP addresses or domain names to scan
* -i a list of IP addresses or domain names to scan
* -d the path to the directory that will be used to save all results of the scans and analyses
* -w Number of worker toperform the scans. By default define to 8


To run properly, at one of the *-i* or *-f*, or both at the same time, is required.
Here is some example of the way to use IDontSpeakSSL:

```
python3 IDontSpeakSSL.py -f scope.txt
python3 IDontSpeakSSL.py -i www.google.com www.facebook.com 10.0.0.1
python3 IDontSpeakSSL.py -f scope.txt -i www.facebook.com 10.0.0.1
python3 IDontSpeakSSL.py -f scope.txt -d result/directory
python3 IDontSpeakSSL.py -f scope.txt -d result/directory -w 16
python3 IDontSpeakSSL.py -t /path/to/testssl/script/testssl.sh -l scope.txt -d result/directory
```

## IPs and domain names list

As parameter IDontSpeakSSL require to send a flat file containing a list of services to scan. This list must be set as follow:

```
10.0.0.1
10.0.0.2
10.0.0.3:8443
www.example.com
www.example.com:8000
```

If a different port than 443 should be scan, the port number must be added after the IP address or the domain name, separeted with a colon.
No protocol should be set a a prefix, as an example https://www.google.com will produce an error.

## Configuration files

This script will read configuration files located in the config folder. The configuration files are following the CSV format. Each line of is confiuration file splitted in three columns and organized as follow:

| Name of the test | Output file of the test | regular expression base 64 encoded  | Title of the finding | Description of the finding |

## Maintainer

trivette - Florian Nivette <fnivette@bishopfox.com>
