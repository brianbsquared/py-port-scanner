import argparse
from scapy.all import *

open_ports = []
closed_ports = []

def scan(ip_addr, port_list):
    for dst_port in port_list:
        src_port = RandShort()
        t = IP(dst=ip_addr)/TCP(sport = src_port, dport = dst_port, flags = 'S')
        resp = sr1(t, timeout=3)
        if(resp is None):
            closed_ports.append(dst_port)
        else:
            if(resp.getlayer(TCP).flags == 0x12):
                open_ports.append(dst_port)
            else:   closed_ports.append(dst_port)




def main():
    print("Hello, there!")

    parser = argparse.ArgumentParser()
    parser.add_argument('-t','--target', help="The IP address to scan", type=str)
    parser.add_argument('-p', '--port', help="The port to scan", type=int)
    args = parser.parse_args()

    port = args.port
    target = args.target


    #scan_ip(host, (80, 81, 22, 12, 1, 8080, 443))
    scan(target, (port,))

    print("Open ports are : " + str(open_ports))
    print("Closed ports are : " + str(closed_ports))

if __name__ == "__main__":
    main()