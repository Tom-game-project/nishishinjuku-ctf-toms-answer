from ptrlib import *

# バイナリのインストール
# scp -P 10004 q4@ctfq.u1tramarine.blue:/home/q4/q4 .

# SSH 接続情報
ssh_host = "ctfq.u1tramarine.blue"
ssh_user = "q4"
ssh_pass = "q60SIMpLlej9eq49"
ssh_port = 10004

remote_binary_path = "/home/q4/q4"

# SSH経由でリモートバイナリを実行
sock = SSH(
    ssh_host,
    ssh_port,
    username = ssh_user,
    password=ssh_pass,
    #command=remote_binary_path
)

sock.sendlineafter("$", "./q4")

# 必要に応じてやりとりを追加
sock.sendafter("What's your name?", b'Tom')

print(sock.recvline())

sock.interactive()

