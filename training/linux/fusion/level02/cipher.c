#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h> // O_RDONLY

#define XORSZ 32

void cipher(unsigned char *blah, size_t len)
{
  static int keyed;
  static unsigned int keybuf[XORSZ];

  int blocks;
  unsigned int *blahi, j;

  if(keyed == 0) {
    int fd;
    fd = open("/dev/urandom", O_RDONLY);
    if(read(fd, &keybuf, sizeof(keybuf)) != sizeof(keybuf)) exit(EXIT_FAILURE);
    close(fd);
    keyed = 1;
  }

  blahi = (unsigned int *)(blah);
  blocks = (len / 4);
  printf("input: %s\n", blah);
  printf("[+] len: %d\n", len);
  printf("[+] blocks: %d\n", blocks);
  printf("[+] len & 3: %d\n", (len & 3));
  if(len & 3) blocks += 1;
  printf("[+] blocks: %d\n", blocks);

  printf("\n");

  int val = 0;
  for(j = 0; j < blocks; j++) {
    val = j % XORSZ;
    printf("[+] j = %d mod XORSZ = %d: %d\n", j, XORSZ, val);
    printf("[+] keybuf[%d]: %hhx\n", val, keybuf[val]);
    blahi[j] ^= keybuf[j % XORSZ]; 
    printf("[+] out[%d]: %hhx\n", j, blahi[j]);
  }
  printf("\n");
}

int main() {

    char str[] = "AAAAB";
    size_t i = 0, len = strlen(str);
    for (i=0; i < len; i++) 
        printf("%d", str[i]);
    printf("\n");
    int lon = len;
    cipher(str, len);
    printf("len: %d\n", len);
    printf("[+] out: ");
    for (i=0; i < len; i++) 
        printf("%hhx", str[i] );
    printf("\n");
    return 0;
}
