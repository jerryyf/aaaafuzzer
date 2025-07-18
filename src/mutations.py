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


def empty_newline() -> str:
    '''
    Returns a newline
    '''
    return '\n'

def empty_str() -> str:
    '''
    Return: An empty string
    '''
    return ''

def empty_xml() -> str:
    '''
    Return: An empty xml
    '''
    return '<></>'

def empty_json() -> str:
    '''
    Return: An empty json
    '''
    return '{}'

def large_str() -> str:
    '''
    Return: A large string padded with 'A'
    '''
    return PAD * MAX_INT

def repeat_sample_input(sample_input, n) -> str:
    '''
    Repeat a file's contents to the power of n.

    Return: Modified sample_input
    '''
    ret = sample_input
    for i in range(n):
        ret += sample_input
    return ret

def bit_flip(sample_input:str, pos:int) -> str:
    '''
    Basic helper to flip bit of sample_input as position pos.
    Sample input cannot exceed str() conversion length

    Return: sample_input as string
    '''
    sample_int = int.from_bytes(sample_input.encode(), 'little') # little endian for x86 32 bit arch
    mask = 1 << pos
    return str(sample_int ^ mask)

def walking_bit_flip(sample_input:str, n:int) -> list:
    '''
    Walking bit flip implementation. Walks up n amount of times starting from 0.

    Return: List of bit flipped inputs.
    '''
    ret = []
    for i in range(n):
        ret += bit_flip(sample_input, i)
    return ret

def random_char_flip(sample_input:str) -> str:
    '''
    Takes a sample_input and flips a random character bit.

    Return: sample_input
    '''
    if sample_input == '':
        return sample_input
    pos = random.randint(0, len(sample_input) - 1)
    char = sample_input[pos]
    bitmask = 1 << random.randint(0, 6)
    char = chr(ord(char) ^ bitmask)
    ret = sample_input[:pos] + char + sample_input[pos + 1:]
    return ret

def random_str(len:int=100, char_start:int=32, char_range:int=32) -> str:
    '''
    Generates a string of up to `max_length` characters in the 
    range [`char_start`, `char_start` + `char_range`)

    Return: string
    '''
    strlen = random.randrange(0, len + 1)
    ret = ''
    for i in range(0, strlen):
        ret += chr(random.randrange(char_start, char_start + char_range))
    return ret

def mutate_file_header(sample_input:bytes) -> str:
    '''
    Given a binary file (such as jpg or pdf)
    mofifies the first 4 bytes randomly.
    '''
    input_arr = bytearray(sample_input)
    random_header = [random.randrange(0, 255),
                  random.randrange(0, 255),
                  random.randrange(0, 255),
                  random.randrange(0, 255)]
    new_arr = bytearray([0,0,0,0])
    for i in range(len(random_header)):
        new_arr[i] = random_header[i]
    
    ret = bytes(new_arr)
    return ret

def n_empty_json(n:int) -> str:
    '''
    Generates a string with {} n amount of times.

    Return: string
    '''
    return '{}' * n

def bigint_value_json(sample_json:str) -> str:
    '''
    Takes a sample json and mutates only int values with large int values.

    Return: sample_json
    '''
    for k in sample_json:
        if type(sample_json[k]) == int:
            sample_json[k] = MAX_INT
    return str(sample_json).replace("'",'"')

def bigstr_value_json(sample_json:str, n:int) -> str:
    '''
    Takes sample json, and int power, and fills each value at each key with cyclic(n)

    Return: sample_json
    '''
    cyclic_str = cyclic(n, alphabet=string.ascii_lowercase)

    for k in sample_json:
        sample_json[k] = cyclic_str
    return str(sample_json).replace("'",'"')

def bigkeys_json(sample_json:str, n:str) -> str:
    '''
    Takes a sample json and int power, replaces each key with a larger key.

    Return: sample_json
    '''
    for i in range(n):
        sample_json[str(i)] = str(i) # can make this random chars
    return str(sample_json).replace("'", '"')


def nested_tags_xml() -> str:
    '''
    Takes sample xml, mutate nested tags

    Return: sample xml
    '''
    res = f"{'<tag>'*100000}"
    res += f"{'</tag>'*100000}"
    return res

def fuzz_content(content, len):
    '''
    Takes sample xml, mutate contents

    Return: sample xml
    '''
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


def read_first_line(sample_file_str) -> str:
    # read file from beginning
    with open(sample_file_str, 'r') as f:
        Lines = f.readlines()
        first_line = Lines[0].strip()
        if first_line:
            return first_line
    return None

def read_index_line(index, sample_file_str) -> str:
    # read file nth line from given index
    with open(sample_file_str, 'r') as f:
        Lines = f.readlines()
        if 0 <= index < len(Lines):
            the_line = Lines[index].strip()
            if the_line:
                return the_line
        return None 

def read_file_lines(sample_file_str) -> int:
    # read file nth line from given index
    with open(sample_file_str, 'r') as f:
        index = 0
        Lines = f.readlines()
        for line in Lines:
            index += 1
    return index

def generate_number_keys_dictionary(path, value):
    key_num = len(path)
    path[key_num] = value
    return path

def compare_path_ret(path) -> bool:
    if len(path) <= 2:
        return False
    
    last = list(path.keys())[-1]
    sec_last = list(path.keys())[-2]
    if last != sec_last:
        return False
    return True

def get_char_menu_list():
    menu = []
    for i in range(26):
        menu.append(chr(ord('a') + i))
    return menu

def get_num_menu_list():
    menu = []
    for i in range(10):
        menu.append(str(i))
    return menu

def get_payload_length(bad_input) -> int:
    payload_length = len(bad_input)
    payload_length += len(bad_input[0]) - 1
    return payload_length


'''
Takes sample xml, mutate string attributes
'''
def find_tags(root, tags) -> str:
    '''
    Takes sample xml, mutate string attributes

    Return: sample xml
    '''
    for _ in root:
        tags.append(_)
        find_tags(_,tags)
    return tags

def fuzz_attri_xml(sample_file_str, character) -> str:
    '''
    Takes sample xml, mutate xml attributes

    Return: sample xml
    '''
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

