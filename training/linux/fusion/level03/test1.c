#include <stdio.h>
#include <string.h>

void func(char * src, char * dest, int len) {
    unsigned char * end = dest + len;
    printf("*src = %s, *dest = %s\n", src, dest);
    while (*src && dest != end) {
        printf("*src = %c, *dest = %c, dest = 0x%x, src+len = 0x%x\n", *src, *(dest-1), (unsigned int)dest, (unsigned int) src+len);
        *dest++ = *src++;
    }
    printf("*src = %s, *dest = %s\n", src, dest);
}

int main() {
    char str1[10] = {0};
    char str2[10] = "----";
    memcpy(str1, "abc", 3);
    func(str1, str2, 3);
    printf("[+] Result: %s\n", str2);
}
