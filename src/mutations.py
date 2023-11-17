import json
import sys
import logging
from pwn import *
import random

MAX_INT = sys.maxsize
PAD = 'A'

# config - debug level won't be logged
logging.basicConfig(filename='/tmp/aaaalog', level=logging.INFO, format='[%(levelname)s] %(asctime)s - %(name)s - %(message)s')

def empty_str() -> str:
    return ''

def empty_json() -> str:
    return '{}'

def large_str() -> str:
    return PAD * MAX_INT

def repeat_sample_input(sample_input, n) -> str:
    '''
    Repeat a file's contents to the power of n.
    '''
    ret = sample_input
    for i in range(n):
        ret += sample_input
    return ret


def bit_flip(sample_input:str, pos:int) -> str:
    '''
    Basic helper to flip bit of sample_input as position pos.
    '''
    sample_int = int.from_bytes(sample_input.encode(), 'little') # little endian for x86 32 bit arch
    mask = 1 << pos
    return str(sample_int ^ mask)

def walking_bit_flip(sample_input:str, n:int) -> list:
    '''
    Walking bit flip implementation. Walks up n amount of times starting from 0.

    Returns list of bit flipped inputs.
    '''
    ret = []
    for i in range(n):
        ret += bit_flip(sample_input, i)
    return ret

def random_char_flip(sample_input:str) -> str:
    '''
    Returns sample_input with a random char bit flipped randomly.
    '''
    if sample_input == '':
        return sample_input
    pos = random.randint(0, len(sample_input) - 1)
    char = sample_input[pos]
    bitmask = 1 << random.randint(0, 6)
    char = chr(ord(char) ^ bitmask)
    ret = sample_input[:pos] + char + sample_input[pos + 1:]
    # print(ret)
    return ret

def random_str(len:int=100, char_start:int=32, char_range:int=32) -> str:
    '''
    A string of up to `max_length` characters
       in the range [`char_start`, `char_start` + `char_range`)
    '''
    strlen = random.randrange(0, len + 1)
    ret = ''
    for i in range(0, strlen):
        ret += chr(random.randrange(char_start, char_start + char_range))
    # print(ret)
    return ret

def n_empty_json(n:int) -> str:
    '''
    Generates a string with {} n amount of times.
    '''
    return '{}' * n

def bigint_value_json(sample_json:str) -> str:
    '''
    Takes a sample json and mutates only int values with large int values.
    '''
    for k in sample_json:
        if type(sample_json[k]) == int:
            sample_json[k] = MAX_INT
    return str(sample_json).replace("'",'"')

def bigstr_value_json(sample_json:str, n:int) -> str:
    '''
    Takes sample json, and int power, and fills each value at each key with cyclic(n)
    '''
    cyclic_str = cyclic(n, alphabet=string.ascii_lowercase)

    for k in sample_json:
        sample_json[k] = cyclic_str
    return str(sample_json).replace("'",'"')

def bigkeys_json(sample_json:str, n:str) -> str:
    for i in range(n):
        sample_json[str(i)] = str(i) # can make this random chars
    return str(sample_json).replace("'", '"')