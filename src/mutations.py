import json
import sys
import logging
from pwn import *

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