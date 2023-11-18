import json
import sys
import copy
import logging
import random
import xml.etree.ElementTree as ET
from pwn import *
import random

MAX_INT = sys.maxsize
PAD = 'A'

# config - debug level won't be logged
logging.basicConfig(filename='/tmp/aaaalog', level=logging.INFO, format='[%(levelname)s] %(asctime)s - %(name)s - %(message)s')

'''
Return: An empty string
'''
def empty_str() -> str:
    return ''

'''
Return: An empty xml
'''
def empty_xml() -> str:
    return '<></>'

'''
Return: An empty json
'''
def empty_json() -> str:
    return '{}'

'''
Return: A large string padded with 'A'
'''
def large_str() -> str:
    return PAD * MAX_INT

'''
Repeat a file's contents to the power of n.

Return: Modified sample_input
'''
def repeat_sample_input(sample_input, n) -> str:
    ret = sample_input
    for i in range(n):
        ret += sample_input
    return ret

'''
Basic helper to flip bit of sample_input as position pos.

Return: sample_input
'''
def bit_flip(sample_input:str, pos:int) -> str:
    sample_int = int.from_bytes(sample_input.encode(), 'little') # little endian for x86 32 bit arch
    mask = 1 << pos
    return str(sample_int ^ mask)

'''
Walking bit flip implementation. Walks up n amount of times starting from 0.

Return: List of bit flipped inputs.
'''
def walking_bit_flip(sample_input:str, n:int) -> list:
    ret = []
    for i in range(n):
        ret += bit_flip(sample_input, i)
    return ret

'''
Takes a sample_input and flips a random character bit.

Return: sample_input
'''
def random_char_flip(sample_input:str) -> str:
    if sample_input == '':
        return sample_input
    pos = random.randint(0, len(sample_input) - 1)
    char = sample_input[pos]
    bitmask = 1 << random.randint(0, 6)
    char = chr(ord(char) ^ bitmask)
    ret = sample_input[:pos] + char + sample_input[pos + 1:]
    return ret

'''
Generates a string of up to `max_length` characters in the 
range [`char_start`, `char_start` + `char_range`)

Return: string
'''
def random_str(len:int=100, char_start:int=32, char_range:int=32) -> str:
    strlen = random.randrange(0, len + 1)
    ret = ''
    for i in range(0, strlen):
        ret += chr(random.randrange(char_start, char_start + char_range))
    return ret

'''
Generates a string with {} n amount of times.

Return: string
'''
def n_empty_json(n:int) -> str:
    return '{}' * n

'''
Takes a sample json and mutates only int values with large int values.

Return: sample_json
'''
def bigint_value_json(sample_json:str) -> str:
    
    for k in sample_json:
        if type(sample_json[k]) == int:
            sample_json[k] = MAX_INT
    return str(sample_json).replace("'",'"')

'''
Takes sample json, and int power, and fills each value at each key with cyclic(n)

Return: sample_json
'''
def bigstr_value_json(sample_json:str, n:int) -> str:
    cyclic_str = cyclic(n, alphabet=string.ascii_lowercase)

    for k in sample_json:
        sample_json[k] = cyclic_str
    return str(sample_json).replace("'",'"')

'''
Takes a sample json and int power, replaces each key with a larger key.

Return: sample_json
'''
def bigkeys_json(sample_json:str, n:str) -> str:
    for i in range(n):
        sample_json[str(i)] = str(i) # can make this random chars
    return str(sample_json).replace("'", '"')


'''
Takes sample xml, mutate nested tags

Return: sample xml
'''
def nested_tags_xml() -> str:
    res = f"{'<tag>'*100000}"
    res += f"{'</tag>'*100000}"
    return res

'''
Takes sample xml, mutate contents

Return: sample xml
'''
def fuzz_content(content, len):
    res = "".join(random.choices(string.ascii_letters + string.digits, k=len))
    return res

def generate_nested_contents(sample_file_str):
    # read file from beginning
    with open(sample_file_str, 'r') as f:
        f.seek(0)
        payload = f.read()
    
    root = ET.fromstring(payload)
    for element in root.iter():
        if element.text is not None:
            element.text = fuzz_content(element.text, 10000)
        
    return ET.tostring(root).decode()

'''
Takes sample xml, mutate string attributes

Return: sample xml
'''
def find_tags(root, tags) -> str:
    for _ in root:
        tags.append(_)
        find_tags(_,tags)
    return tags

'''
Takes sample xml, mutate xml attributes

Return: sample xml
'''
def fuzz_attri_xml(sample_file_str, character) -> str:
    print("Fuzzing the XML formatted sample input...\n", end="")
    with open(sample_file_str, 'r') as f:
        f.seek(0)
        payload = f.read()

    root = ET.fromstring(payload)
    all_tags = find_tags(root, [])
    attribute_herf = [tag for tag in all_tags if 'href' in tag.attrib]

    fill = character*100
    for tag in attribute_herf:
        tag.set('href', fill)
        
    return ET.tostring(root).decode()

