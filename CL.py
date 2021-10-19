from socket import *
from threading import Thread
import re
from colorama import init
import getpass

def setport():
    while True:
        port = input("[SET PORT] - ")
        if len(port) <= 5 and port.isdigit():
            port = int(port)
            break
        elif not port:
            port = 9090
            break
        else:
            print("[ERROR] Invalid port name")
    return port


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
            host = 'localhost'
            break
        elif is_valid_hostname(host):
            break
        else:
            print("[ERROR] Invalid host name")

    return host


def receive():
    while True:
        msg = client_socket.recv(BUFSIZ).decode("utf8")
        if msg == "{exit}":
            client_socket.close()
            break
        if not msg:
            break
        print(msg)


def send():
    while True:
        try:
            msg = input("")
            client_socket.send(bytes(msg, "utf8"))
            if msg == "{exit}":
                break
        except:
            client_socket.close()
            break


init()

HOST = sethost()
PORT = setport()

BUFSIZ = 1024
ADDR = (HOST, PORT)

client_socket = socket(AF_INET, SOCK_STREAM)
client_socket.connect(ADDR)

receive_thread = Thread(target=receive)
send_thread = Thread(target=send)
receive_thread.start()
send_thread.start()
receive_thread.join()
send_thread.join()
