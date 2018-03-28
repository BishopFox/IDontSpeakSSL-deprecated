# IDontSpeakSSL

IDontSpeakSSL is a simple script to made parse testssl.sh results. It's purpose is to automate the discovery of bad practices on SSL/TLS confiuration, Cipher suites and Certificates.
It is useful on large scope, for example during internal or external penetration testing.

## Usage

This script need 3 argument to run. These areguments are:
* -t the path to the testssl.sh script
* -l the path to file containing the list of IP addresses or domain names to scan
* -d the path to the directory that will be used to save all results of the scans and analyses


## TODO

List of different things to do in order to improve this script:
* Multi-thread
* Scan elliptic curves, but to patch an elliptic curves you need to recompile openssl
* ...

## Maintainer

trivette - Florian Nivette <fnivette@bishopfox.com>
