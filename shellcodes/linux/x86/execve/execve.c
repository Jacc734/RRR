#include <unistd.h>

int main (void) {
    char * shell[2];
    shell[0] = "/bin/sh";
    shell[1] = 0;
    execve("/bin/sh", shell, NULL);
}
