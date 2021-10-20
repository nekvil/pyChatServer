import json
import logging
import os
import re
import signal
import time
import socket
from threading import Thread
from colorama import init
import bcrypt


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def commands():
    while True:
        try:
            n = input("")
            if n.isspace() or n == "":
                continue
            elif n == "{exit}":
                break
            elif n == "cls":
                cls()
                continue
            elif n == "rdlog":
                rdlog()
                continue
            elif n == "cllog":
                cllog()
                continue
            elif n == "cldata":
                cldata()
                continue
            elif n == "help":
                help()
                continue
            else:
                print("\033[31m" + ('[ERROR] Unknown command ' + "\""+str(n)+"\"."+'Try help') + '\033[0m')
                continue
        except:
            print("\033[31m" + ('[ERROR] Unknown command ' + "\""+str(n)+"\"."+'Try help') + '\033[0m')
            continue
    os.kill(os.getpid(), signal.SIGTERM)


def help():
    print(f"{bcolors.OKGREEN}{{exit}} - Exit from program")
    print("cls - Сlear the console")
    print("rdlog - Read log file")
    print("cllog - Clear log file")
    print(f"cldata - Clear data file{bcolors.ENDC}")
    return


def cls():
    return os.system('cls' if os.name == 'nt' else 'clear')


def cldata():
    try:
        open('data.json', 'w').close()
        print(f"{bcolors.OKGREEN}[INFO] Successfully cleaned data file{bcolors.ENDC}")
    except:
        print(f"{bcolors.FAIL}[ERROR] File does not exist{bcolors.ENDC}")
    return


def cllog():
    try:
        open('app.log', 'w').close()
        print(f"{bcolors.OKGREEN}[INFO] Successfully cleaned log file{bcolors.ENDC}")
    except:
        print(f"{bcolors.FAIL}[ERROR] File does not exist{bcolors.ENDC}")
    return


def rdlog():
    try:
        with open('app.log') as fd:
            lines = fd.readlines()
        for line in lines:
            print(line.strip())
        print(f"{bcolors.OKGREEN}[INFO] Ended reading log file{bcolors.ENDC}")
    except:
        print(f"{bcolors.FAIL}[ERROR] File does not exist{bcolors.ENDC}")
    return


def gettimestamp():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def check_password(data):
    return re.fullmatch(r'^((?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%&*]))((.)(?!\3{3})){8,26}$', data)


def check_free_port(port, rais=True):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('127.0.0.1', port))
        sock.listen(5)
        sock.close()
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.bind(('::1', port))
        sock.listen(5)
        sock.close()
    except socket.error as e:
        if rais:
            print(f"{bcolors.WARNING}[WARNING] The server is already running on port {port} {bcolors.ENDC}")
            logging.warning(f"[WARNING] The server is already running on port {port}")
        return False
        # if rais:
        #     raise RuntimeError(
        #         "The server is already running on port {0}".format(port))
    return True


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


def accept_incoming_connections():
    while True:
        client, client_address = SERVER.accept()
        print(f"{bcolors.OKGREEN}[NEW CONNECTION {gettimestamp()}] {client_address[0]}:{client_address[1]} has connected{bcolors.ENDC}")
        logging.info(f"[NEW CONNECTION {gettimestamp()}] {client_address[0]}:{client_address[1]} has connected")
        Thread(target=handle_client, args=(client, client_address)).start()


def handle_client(client, client_address):
    try:
        user = {}
        with open("data.json", "r") as read_file:
            json_addresses = json.load(read_file)

        # address = f"{client_address[0]}:{client_address[1]}"
        address = f"{client_address[0]}"

        if address in json_addresses:

            name = json_addresses[address]["name"]
            client.send(bytes(f"{bcolors.OKGREEN}[INFO] Welcome back, {name}!{bcolors.ENDC}", "utf8"))
            # Вход в аккаунт
            try_count = 4
            while True:
                client.send(bytes("[PASSWORD] Type your password and press enter", "utf8"))
                password = client.recv(BUFSIZ).decode("utf8")

                if bcrypt.checkpw(bytes(password, "utf8"), json_addresses[address]["password"].encode("utf8")):
                    client.send(bytes(f"{bcolors.OKGREEN}[INFO] Successfully logging{bcolors.ENDC}", "utf8"))
                    break
                elif try_count == 0:
                    client.send(bytes(
                        f"{bcolors.FAIL}[ERROR] You have exceeded the number of allowed attempts to sign in{bcolors.ENDC}",
                        "utf8"))
                    client.close()
                    break
                else:
                    client.send(
                        bytes(f"{bcolors.WARNING}[WARNING] Wrong password. Try again{bcolors.ENDC}", "utf8"))
                    try_count -= 1

        else:

            client.send(bytes("[NAME] Type your name and press enter", "utf8"))
            name = client.recv(BUFSIZ).decode("utf8")
            user["name"] = name

            while True:
                client.send(bytes("[PASSWORD] Type your password and press enter", "utf8"))
                password = client.recv(BUFSIZ).decode("utf8")
                if not check_password(password):
                    client.send(bytes(
                        f"{bcolors.WARNING}[WARNING] Your password must be at least 8 characters long, be of mixed case and also contain a digit or symbol.{bcolors.ENDC}",
                        "utf8"))
                else:
                    break
            user["password"] = bcrypt.hashpw(bytes(password, "utf8"), bcrypt.gensalt()).decode('utf8')

            addresses[address] = user
            json_addresses.update(addresses)

            with open('data.json', 'w', encoding='utf-8') as f:
                json.dump(json_addresses, f, ensure_ascii=False, indent=4)

        welcome = f'Hello {bcolors.OKGREEN}{name}{bcolors.ENDC}! If you ever want to quit, type {bcolors.WARNING}{{exit}}{bcolors.ENDC} to exit.'
        client.send(bytes(welcome, "utf8"))

        msg = f"{bcolors.OKGREEN}[JOIN {gettimestamp()}] {name} has joined the chat{bcolors.ENDC}"
        broadcast(bytes(msg, "utf8"))

        clients[client] = name

        while True:
            msg = client.recv(BUFSIZ)
            if msg != bytes("{exit}", "utf8"):
                broadcast(msg, f"[MESSAGE {gettimestamp()}] " + bcolors.OKGREEN + name + bcolors.ENDC + ": ")
                print(f"[MESSAGE {gettimestamp()}] {bcolors.OKGREEN}{name}{bcolors.ENDC}: {msg.decode()}")

                logging.info(f"[MESSAGE {client_address[0]} {gettimestamp()}] {name}: {msg.decode()}")
            else:
                client.send(bytes("{exit}", "utf8"))
                client.close()

                print(
                    f"{bcolors.WARNING}[NEW DISCONNECTION {gettimestamp()}] {client_address[0]}:{client_address[1]} has disconnected{bcolors.ENDC}")
                logging.info(
                    f"[NEW DISCONNECTION {gettimestamp()}] {client_address[0]}:{client_address[1]} has disconnected")

                del clients[client]
                broadcast(
                    bytes(f"{bcolors.WARNING}[LEFT {gettimestamp()}] {name} has left the chat{bcolors.ENDC}", "utf8"))
                break
    except:
        client.close()
        print(
            f"{bcolors.WARNING}[NEW DISCONNECTION {gettimestamp()}] {client_address[0]}:{client_address[1]} has disconnected{bcolors.ENDC}")
        logging.info(f"[NEW DISCONNECTION {gettimestamp()}] {client_address[0]}:{client_address[1]} has disconnected")
        return


def broadcast(msg, prefix=""):  # prefix is for name identification.
    for sock in clients:
        sock.send(bytes(prefix, "utf8") + msg)


init()
addresses = {}
clients = {}
logging.basicConfig(level=logging.DEBUG, filename='app.log', filemode='a',
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    datefmt='%d-%b-%y %H:%M:%S')

HOST = ''
PORT = setport()
BUFSIZ = 1024

SERVER = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

if check_free_port(PORT):
    SERVER.bind((HOST, PORT))
else:
    SERVER.bind((HOST, 0))

if not os.path.exists('data.json'):
    with open('data.json', 'w+', encoding='utf-8') as f:
        json.dump(addresses, f, ensure_ascii=False, indent=4)

if __name__ == "__main__":

    print(f"{bcolors.OKGREEN}[STARTING] Server is starting...{bcolors.ENDC}")
    logging.info("[STARTING] Server is starting...")

    print(f"[BINDING] Binding address {SERVER.getsockname()[0]}:{SERVER.getsockname()[1]}")
    logging.info(f"[BINDING] Binding address {SERVER.getsockname()[0]}:{SERVER.getsockname()[1]}")

    print(f"[LISTENING {gettimestamp()}] Server is listening on {SERVER.getsockname()[0]}:{SERVER.getsockname()[1]}")
    logging.info(
        f"[LISTENING {gettimestamp()}] Server is listening on {SERVER.getsockname()[0]}:{SERVER.getsockname()[1]}")

    SERVER.listen(5)

    print("[WAITING] Waiting for connection...")
    logging.info("[WAITING] Waiting for connection...")

    ACCEPT_THREAD = Thread(target=accept_incoming_connections)
    MAIN_THREAD = Thread(target=commands)
    MAIN_THREAD.start()
    ACCEPT_THREAD.start()
    ACCEPT_THREAD.join()
    MAIN_THREAD.join()
    SERVER.close()
