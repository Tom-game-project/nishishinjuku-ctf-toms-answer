# ROP(Return Oriented Programming)

## エクスプロイトプログラム実行時にメモリの様子をgdbで観察する方法

- エクスプロイト用のプログラムのどこかに`input()`をいれて待ってもらう

- 権限を一時的に変更して別プロセスを見れるようにする

```bash
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```

- 実行して判明したプロセスidを指定してgdbを起動する

```bash
gdb -p <proc id>
```

## rop時に起こりがちな問題と対処

- rop時に起こりがちなsegvへの対処

大体は16bitアラインメント系のinstruction由来の問題（simd系のmmなんとかみたいな命令)

そんなときは、retする（スタックに書き込む）または、関数の先頭に必ずあるであろうpush命令をスキップする（*main_addr + 6みたいな感じで）要は、余分にスタックが一個積まれている状態になっていればok
