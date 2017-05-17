from pwn import *

conn = remote('pwnable.kr', 9007)
conn.recvuntil('starting in 3 sec... -\n')
conn.recvline()

for i in range(100):
    res = conn.recvline()
    print "[Server]: ", res
    res_tokens = res.split()
    N = int(res_tokens[0].split('=')[1])
    C = int(res_tokens[1].split('=')[1])

    low = 0
    hi = N - 1
    query = 0
    while hi != low :
        mid = (low + hi) / 2 + 1
        req = ' '.join(map(lambda x: str(x), range(low, mid)))
        print "[Client]: ", req
        conn.sendline(req)
        query += 1
        res = conn.recvline()
        print "[Server]: ", res
        real_weight = int(res)
        coins = mid - low
        ideal_weight = 10 * coins
        if real_weight < ideal_weight:
            hi = mid - 1
        else:
            low = mid

    if real_weight < ideal_weight:
        fake_coin = hi
    else:
        fake_coin = low

    if query < C:
        print "[Client]: ", req
        conn.sendline(req)
        res = conn.recvline()
        print "[Server]: ", res

    print "[Client]: ", fake_coin
    conn.sendline(str(fake_coin))
    res = conn.recvline()
    print res

flag = conn.recv()
print "[Flag]: ", flag