

char shellcode[] = 
        "SHELLCODE HERE";

int main(int argc, char **argv) {

    void (*func) (void);
    func = (void *) shellcode;
    func();

    return 0;
}
