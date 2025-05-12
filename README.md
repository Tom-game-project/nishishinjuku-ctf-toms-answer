# CTF

## FSB(書式文字列攻撃)

printfの第一引数をユーザーが自由に操作可能な場合にできる攻撃


`fsb/fsb.py`

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
uv run fsb/fsb.py
```

## ROP(Return Oriented Programming)

ユーザーがスタック領域に書き込める場合(関数内で使用する変数をオーバーフローさせられる場合など)ときに、return アドレスを書き換えて任意の関数を実行する攻撃手法

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
uv run fsb/fsb.py
```

## got over write

プログラムが遅延的にアドレス解決をする仕組みを利用して、リークして判明したベースアドレスからgotアドレスを書き換える攻撃手法

`fsb/fsb.py`にも使われている

