#include <stdio.h>
#include <string.h>

void func(char * dest) {
    int what = 0x4455, i = 0;
    while (i < 8) {
        int lol = what >> 8;
        printf("what>>8 & 0xff: %x\n", lol & 0xff);
        *dest++ = (what >> 8) & 0xff;
        printf("what & 0xff: %x\n", what & 0xff);
        *dest++ = (what & 0xff);
        printf("[+] Result: %x\n", *dest++);
        i++;
    }
    printf("[+] Result: %s\n", dest);
}

int main() {
    unsigned char dest[10] = "AAAAAAAAAA";
    func(dest);
}
