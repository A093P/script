This script enumerates and scans subdomains, then outputs a .csv file from nmap and a .txt file from assetfinder
 

DESCRIPTION

This script executes subdomain enumeration of a given domain; if passive mode is not specified, it executes a port scan using Nmap. 

It supports two execution modes:
 
- PASSIVE MODE: It only enumerates subdomains, without scanning ports
- ACTIVE MODE:  Enumeration followed by port scan with Nmap
 
The output file has been optimized for readability
 
 
PREREQUISITES

Ensure you have installed the following tools:

- Go language
 
- assetfinder → go install github.com/tomnomnom/assetfinder@latest

- nmap → sudo apt install nmap (Debian/Ubuntu)

- awk, getent, column (Usually preinstalled)

- proxychains → sudo apt-get install proxychains4
 


USAGE


sudo bash ./script.sh -d [domain] -p -m [passive/active]
