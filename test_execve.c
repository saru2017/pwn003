#include <stdio.h>

int main()
{
    char *argv[] = {"/bin/sh", NULL};
    execve(argv[0], argv, NULL);
}

