import json
import sys
import copy
import logging
import random
import xml.etree.ElementTree as ET
from pwn import *

MAX_INT = sys.maxsize
PAD = 'A'

# config - debug level won't be logged
logging.basicConfig(filename='/tmp/aaaalog', level=logging.INFO, format='[%(levelname)s] %(asctime)s - %(name)s - %(message)s')

def empty_str() -> str:
    return ''

def empty_xml() -> str:
    return '<></>'

def empty_json() -> str:
    return '{}'

def large_str() -> str:
    return PAD * MAX_INT

'''
Repeat a file's contents to the power of n.
'''
def repeat_sample_input(sample_input, n) -> str:
    with open(sample_input, 'r') as inf:
        content = inf.read()
        for i in range(n):
            content += content
    return content

'''
Generates a string with {} n amount of times.
'''
def n_empty_json(n:int) -> str:
    return '{}' * n

'''
Takes a sample json and mutates only int values with large int values.
'''
def bigint_value_json(injson:str) -> str:
    with open(injson, 'r') as inf:
        jsondict = json.load(inf)
        logging.info('JSON sample input: ' + str(jsondict))
        for k in jsondict:
            if type(jsondict[k]) == int:
                jsondict[k] = MAX_INT
    return str(jsondict).replace("'",'"')

'''
Takes sample json, and int power, and fills each value at each key with cyclic(n)
'''
def bigstr_value_json(injson:str, n:int) -> str:
    with open(injson, 'r') as inf:
        jsondict = json.load(inf)
        logging.info('JSON sample input: ' + str(jsondict))

        cyclic_str = cyclic(n, alphabet=string.ascii_lowercase)

        for k in jsondict:
            jsondict[k] = cyclic_str
    return str(jsondict).replace("'",'"')

def bigkeys_json(injson:str, n:str) -> str:
    with open(injson, 'r') as inf:
        jsondict = json.load(inf)
        logging.info('JSON sample input: ' + str(jsondict))
        for i in range(n):
            jsondict[str(i)] = str(i) # can make this random chars
    return str(jsondict).replace("'", '"')


'''
Takes sample xml, mutate nested tags
'''
def nested_tags_xml() -> str:
    res = f"{'<tag>'*100000}"
    res += f"{'</tag>'*100000}"
    return res

'''
Takes sample xml, mutate contents
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
'''
def find_tags(root, tags) -> str:
    for _ in root:
        tags.append(_)
        find_tags(_,tags)
    return tags

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

