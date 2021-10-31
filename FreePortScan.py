import re
from datetime import datetime
from socket import socket, AF_INET, SOCK_STREAM
from threading import Thread
from progress.bar import ChargingBar


def scan_port(ip, port):
    sock = socket(AF_INET, SOCK_STREAM)
    sock.settimeout(0.5)
    try:
        connect = sock.connect((ip, port))
        free_port_list.append(port)
        # print('\nPort:', port, 'its open.')
        sock.close()
    except:
        pass


def is_valid_hostname(hostname):
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1]  # strip exactly one dot from the right, if present
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))


def sethost():
    while True:
        host = input("[SET HOST] - ")
        if not host:
            host = '192.168.0.1'
            break
        elif is_valid_hostname(host):
            break
        else:
            print("[ERROR] Invalid host name")

    return host


HOST = sethost()
port_number = 2 ** 16

bar = ChargingBar('Searching free ports', max=port_number)
free_port_list = []
start = datetime.now()

for i in range(port_number):
    scan_tread = Thread(target=scan_port, args=(HOST, i))
    bar.next()
    scan_tread.start()

bar.finish()
ends = datetime.now()
print('Time: {}'.format(ends - start), end="")
print("\nFree ports:", sorted(free_port_list))
