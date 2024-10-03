from secrets import token_bytes

S = list(range(256))
i = j = 0

# .ivs format (tentative): AE78D1FF0100 then repeat: 08001300 IV(3b) 00 OUTPUT(15b)
dp = "/path/to/output/dir/"

def ks(key):
    global S, i, j # make this output?
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i%len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0

def output():
    global i, j
    i = (i + 1) % 256
    j = (j  + S[i]) % 256
    S[i], S[j] = S[j], S[i]
    return S[(S[i] + S[j]) % 256]

def gen_ivs(key, filename, outs=15, num=30000):
    if not (0<=outs<=251): raise ValueError("outs must be between 0 and 251")
    file = open(filename, "wb")
    file.write(bytes([0xAE, 0x78, 0xD1, 0xFF, 0x01, 0x00]))
    for __ in range(num):
        iv = token_bytes(3)
        ks(list(iv)+key)
        out = bytes(output() for ___ in range(outs))
        file.write(bytes([0x08, 0x00, outs+4, 0x00])+iv+b'\x00'+out)
    file.close()

def sbyte(key, index, init):
    if not init<=index: raise ValueError("start index cannot be later than end")
    acc = 0
    for ki in range(init, index):
        acc = (acc + key[ki] + ki + 3) % 256
    return (-acc - index - 3) % 256

def slist(key):
    sl = []
    for sb in range(13):
        for ib in range(sb+1):
            if key[sb] == sbyte(key, sb, ib): sl.append((sb, ib))
    return sl

def is_str(key):
    for sb in range(13):
        for ib in range(sb+1):
            if key[sb] == sbyte(key, sb, ib): return True
    return False