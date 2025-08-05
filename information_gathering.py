from importlib.metadata import requires
from sys import argv, exit
from colorama import init,Fore
import requests
from whois import whois
from dns import resolver
from shodan import Shodan
import requests
from argparse import ArgumentParser
import socket
# here I import my all libraries.

red=Fore.RED
blue=Fore.BLUE
yellow=Fore.YELLOW
cyan=Fore.CYAN
reset=Fore.RESET


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
if not (args.dns or args.geo) or args.all:

    try:
        print(f"{red}[+] whois getting info....{reset}")
        py=whois(domain)
        print(f"{red}[+] whois information found.{reset} ")
        print(f"{blue}name:{reset} {yellow}{py.name}{reset}")
        print(f"{blue}registrar:{reset}{yellow}{py.registrar}{reset}")
        print(f"{blue}Creation date:{reset} {yellow}{py.creation_date}{reset}")
        print(f"{blue}Expiration date:{reset} {yellow}{py.expiration_date}{reset}")
        print(f"{blue}Registrant:{reset}{yellow} {py.registrant}{reset}")
        print(f"{blue}Registrant country:{reset} {yellow} {py.registrant_country}{reset}")
    # whois module used for domain information
    except:
        pass
print()
print()

print(f"{cyan}----------------------------------------------------------------------------{reset}")
# dns module
if args.dns or args.all:
    print(f"{red}[+] getting DNS information....{reset}")
    try:
        for a in resolver.resolve(domain,'A'):
            print(f"{blue}[+] A record:{reset} {yellow}{a.to_text()}{reset}")

    except:
        pass
    try:
        for MX in resolver.resolve(domain, 'MX'):
            print(f"{blue}[+] MX record:{reset} {yellow}{MX.to_text()}{reset}")

    except:
        pass
    try:
        for NS in resolver.resolve(domain, 'NS'):
            print(f"{blue}[+] NS record:{reset} {yellow}{NS.to_text()}{reset}")

    except:
        pass
    try:
        for TXT in resolver.resolve(domain, 'TXT'):
            print(f"{blue}[+] TXT record:{reset} {yellow}{TXT.to_text()}{reset}")

    except:
        pass
    try:
        for AAAA in resolver.resolve(domain, 'AAAA'):
            print(f"{blue}[+] AAAA record:{reset}{yellow} {AAAA.to_text()}{reset}")

    except:
        pass
print()
print()
print(f"{cyan}----------------------------------------------------------------------------{reset}")
# module geolocation
if args.geo or args.all:
    print(f"{red}[+++++] getting geo location information....[+++++]{reset}")
    try:
        response = requests.request('GET', "https://geolocation-db.com/json/" + socket.gethostbyname(domain)).json()
        print(f"{red}[+] found geolocation information  .{reset}")
        print(f"{blue}[+] COUNTRY NAME:{reset}{yellow} {response['country_name']}{reset}")
        print(f"{blue}[+] LATITUDE:{reset}{yellow} {response.get('latitude')}{reset}")
        print(f"{blue}[+] LONGITUDE:{reset} {yellow}{response.get('longitude')}{reset}")
        print(f"{blue}[+] CITY:{reset} {yellow}{response.get('city')}{reset}")
        print(f"{blue}[+] COUNTRY CODE:{reset}{yellow} {response.get('country_code')}{reset}")
        print(f"{blue}[+] STATE:{reset}{yellow} {response.get('state')}{reset}")
        print(f"{blue}[+] POSTAL:{reset} {yellow}{response.get('postal')}{reset}")
        print(f"{blue}[+] IPV4:{reset}{yellow} {response.get('IPv4')}{reset}")
    except Exception as e:
        print(f"{red}[-] Geolocation not found.{reset}")
        print("[-] Error:", e)


