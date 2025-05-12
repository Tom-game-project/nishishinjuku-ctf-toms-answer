# ROP(Return Oriented Programming)

## pythonのエクスプロイトプログラム実行時のメモリの様子を、gdbを使って観察する方法

- エクスプロイト用のプログラムのどこかに`input()`をいれて待ってもらう

- 別プロセスを見れるようにする

```bash
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```

- 実行して判明したプロセスidを指定してgdbを起動する

```bash
gdb -p <proc idd>
```

rop時に起こりがちなsegvへの対処
大体は16bitアラインメント系のinstruction由来の問題（simd系のmmなんとかみたいな命令)

そんなときは、retする（スタックに書き込む）または、関数の先頭に必ずあるであろうpush命令をスキップする（*main_addr + 6みたいな感じで）要は、余分にスタックが一個積まれている状態になっていればok
