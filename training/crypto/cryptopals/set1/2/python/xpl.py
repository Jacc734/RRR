#!/usr/bin/env python

i1 = '1c0111001f010100061a024b53535009181c'.decode('hex')
i2 = '686974207468652062756c6c277320657965'.decode('hex')

res = []
i = 0
while (i < len(i1)):
    res.append(chr(ord(i1[i]) ^ ord(i2[i])))
    i+= 1
res = ''.join(res)

print("First method (base64): {0}".format(res.encode('base64', 'strict').strip()))
print("First method (hex): {0}".format(res.encode('hex', 'strict')))




# Good way
def strxor(a, b):     # xor two strings of different lengths
    if len(a) > len(b):
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])
    else:
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])

result = strxor(i1, i2)
print("Second method (base64): {0}".format(result.encode('base64', 'strict').strip()))
print("Second method (hex): {0}".format(result.encode('hex', 'strict')))
