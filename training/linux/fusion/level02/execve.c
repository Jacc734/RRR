int main() {
    char *argv[] = {"AAAA", 0};
    execve("/bin/ls", argv, 0);
}
