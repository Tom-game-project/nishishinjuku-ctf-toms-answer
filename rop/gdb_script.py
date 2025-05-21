import gdb

gdb.execute("b *main+137")
gdb.execute("c")
gdb.execute("c")
