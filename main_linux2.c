#include <stdio.h>
#include <string.h>

void f()
{
    __asm("int $0x80");

    __asm("inc %eax");
    __asm("ret");

    __asm("xor %eax,%eax");
    __asm("ret");

    __asm("mov %eax,(%edx)");
    __asm("ret");

    __asm("pop %eax");
    __asm("ret");

    __asm("pop %ebx");
    __asm("ret");

    __asm("pop %ecx");
    __asm("ret");

    __asm("pop %edx");
    __asm("ret");
}
int main(int argc, char **argv)
{
    char buff[100];
    strcpy(buff, argv[1]);
    printf("buff = %s\n", buff);
    printf("%d\n", strlen(buff)); 
    return (0);
}
