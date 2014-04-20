 1#include "../common/common.c"  
 2
 3int fix_path(char *path)
 4{
 5  char resolved[128];
 6  
 7  if(realpath(path, resolved) == NULL) return 1; // can't access path. will error trying to open
 8  strcpy(path, resolved);
 9}
10
11char *parse_http_request()
12{
13  char buffer[1024];
14  char *path;
15  char *q;
16
17  printf("[debug] buffer is at 0x%08x :-)\n", buffer);
18
19  if(read(0, buffer, sizeof(buffer)) <= 0) errx(0, "Failed to read from remote host");
20  if(memcmp(buffer, "GET ", 4) != 0) errx(0, "Not a GET request");
21
22  path = &buffer[4];
23  q = strchr(path, ' ');
24  if(! q) errx(0, "No protocol version specified");
25  *q++ = 0;
26  if(strncmp(q, "HTTP/1.1", 8) != 0) errx(0, "Invalid protocol");
27
28  fix_path(path);
29
30  printf("trying to access %s\n", path);
31
32  return path;
33}
34
35int main(int argc, char **argv, char **envp)
36{
37  int fd;
38  char *p;
39
40  background_process(NAME, UID, GID);  
41  fd = serve_forever(PORT);
42  set_io(fd);
43
44  parse_http_request();  
45}
