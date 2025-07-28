from importlib.metadata import requires
from sys import argv, exit

import requests
from whois import whois
from dns import resolver
from shodan import Shodan
import requests
from argparse import ArgumentParser
import socket
# here I import my all libraries.

argument_parser = ArgumentParser(
    description="This tool is used for information gathering",
    usage="python information_gathering.py -d DOMAIN [-x] [-n] [-g] [-s IP]",
    epilog="Somnath Sing Patar"
)

# argument_parser=ArgumentParser(description="This tool is use for information gathering ",usage="Python3 information_gathering.py -d DOMAIN [ -s IP ]  ")
argument_parser.add_argument("-d","--domain",help="Enter the domain name for footprinting. ",required=True)
# argument_parser.add_argument("-s","--shodan",help="Enter the ip for shodan search .", action="store_true")
argument_parser.add_argument("-n","--dns",help="For dns information only", action="store_true")
argument_parser.add_argument("-g","--geo",help="For geolocation only", action="store_true")
argument_parser.add_argument("-x","--all",help="For all(DNS , GEOLOCATION and WHOIS)", action="store_true")

args= argument_parser.parse_args()
domain=args.domain


# then have made an object named "argument_parser" and initialized  keyword arguments (or named parameters)

# whois module
if not (args.dns or args.geo or args.all):
    try:
        print("[+] whois getting info....")
        py=whois(domain)
        print("[+] whois information found. ")
        print("name: {}".format(py.name))
        print("registrar:{}".format(py.registrar))
        print("Creation date: {}".format(py.creation_date))
        print("Expiration date: {}".format(py.expiration_date))
        print("Registrant: {}".format(py.registrant))
        print("Registrant country: {}".format(py.registrant_country))
    # whois module used for domain information
    except:
        pass
print()
print()

print("----------------------------------------------------------------------------")
# dns module
if args.dns or args.all:
    print("[+] getting DNS information....")
    try:
        for a in resolver.resolve(domain,'A'):
            print("[+] A record: {}".format(a.to_text()))

    except:
        pass
    try:
        for MX in resolver.resolve(domain, 'MX'):
            print("[+] MX record: {}".format(MX.to_text()))

    except:
        pass
    try:
        for NS in resolver.resolve(domain, 'NS'):
            print("[+] NS record: {}".format(NS.to_text()))

    except:
        pass
    try:
        for TXT in resolver.resolve(domain, 'TXT'):
            print("[+] TXT record: {}".format(TXT.to_text()))

    except:
        pass
    try:
        for AAAA in resolver.resolve(domain, 'AAAA'):
            print("[+] AAAA record: {}".format(AAAA.to_text()))

    except:
        pass
print()
print()
print("----------------------------------------------------------------------------")
# module geolocation
if args.geo or args.all:
    print("[+++++] getting geo location information....[+++++]")
    try:
        response = requests.request('GET', "https://geolocation-db.com/json/" + socket.gethostbyname(domain)).json()
        print("[+] found geolocation information  .")
        print("[+] COUNTRY NAME: {}".format(response['country_name']))
        print("[+] LATITUDE: {}".format(response['latitude']))
        print("[+] LONGITUDE: {}".format(response['longitude']))
        print("[+] CITY: {}".format(response['city']))
        print("[+] COUNTRY CODE: {}".format(response['country_code']))
        print("[+] STATE: {}".format(response['state']))
        print("[+] POSTAL: {}".format(response['postal']))
        print("[+] IPV4: {}".format(response['IPv4']))
    except Exception as e:
        print("[-] Geolocation not found.")
        print("[-] Error:", e)



