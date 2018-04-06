# IDontSpeakSSL

IDontSpeakSSL is a simple script to made parse testssl.sh results. It's purpose is to automate the discovery of bad practices on SSL/TLS confiuration, Cipher suites and Certificates.
It is useful on large scope, for example during internal or large external penetration testing.

To use this script, you will need to get testssl.sh first, [testssl.sh](https://testssl.sh/).

**IT'S A PYTHON 3 SCRIPT**

## Usage

This script need 3 argument to run. These areguments are:
* -t the path to the testssl.sh script
* -l the path to file containing the list of IP addresses or domain names to scan
* -d the path to the directory that will be used to save all results of the scans and analyses

```
python3 -t /path/to/testssl/script/testssl.sh -l scope.txt -d result/directory
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

## TODO

List of different things to do in order to improve this script:
* Multi-thread
* Use ncurse for interfacing
* Scan elliptic curves, but to patch an elliptic curves you need to recompile openssl
* ...

## Maintainer

trivette - Florian Nivette <fnivette@bishopfox.com>
