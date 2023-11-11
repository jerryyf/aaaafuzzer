from pwn import *
import json
import subprocess
import logging
from harness import detect_crash

MAX_INT = sys.maxsize
LARGE_CHAR = cyclic(10000)
PAD = "A"


# config - debug level won't be logged
logging.basicConfig(filename='/tmp/aaaalog', level=logging.INFO, format='[%(levelname)s] %(asctime)s - %(name)s - %(message)s')
context.cyclic_alphabet = string.ascii_lowercase


def fuzz_rows(binary_file, binary_input, target_output):
    binary_input.seek(0)
    payload = binary_input.readline()

    for i in range(0, 100):
        badpayload = (payload * i * 100)

    ret = subprocess.run(binary_file, input=badpayload, stdout=subprocess.PIPE, text=True)

    if ret.returncode != 0:
        log.critical(f"Program crashed, returned {ret.returncode}. Check /tmp/aaaalog for details. bad.txt generated at /tmp/bad.txt")
        with open(target_output, 'a') as badcsv:
            badcsv.write(badpayload)


def fuzz_colns(binary_file, binary_input, target_output):
    # read file from begining
    binary_input.seek(0)
    lines = [line.rstrip() for line in binary_input]

    # create a list for values going to be modified
    payload = []
    for item in lines:
        first_row = item.strip().split(",")

        # try fuzzing forst column
        for i in range(0, len(first_row)):
            first_row[i] = PAD*15

        # join the modified contents
        badline = ",".join(first_row)
        payload.append(badline + '\n')
    
    badpayload = "".join(payload)

    ret = subprocess.run(binary_file, input=badpayload, stdout=subprocess.PIPE, text=True)

    if ret.returncode != 0:
        log.critical(f"Program crashed, returned {ret.returncode}. Check /tmp/aaaalog for details. bad.txt generated at /tmp/bad.txt")
        with open(target_output, 'a') as badcsv:
            badcsv.write(badpayload)


def fuzz_csv(binary_file, binary_input, target_output):

    if fuzz_rows(binary_file, binary_input, target_output):
        log.info(f"Found vulnerability on fuzzing rows!...")

    if fuzz_colns(binary_file, binary_input, target_output):
        log.info(f"Found vulnerability on fuzzing columns!...")


def empty_file() -> str:
    return ''

def empty_json() -> str:
    return '{}'

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

        cyclic_str = cyclic(n)

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
Generate and run a JSON bad.txt against binary. Log, write the bad input to bad.txt and exit if program exits with a non-zero status.

Returns: the return code of the binary
'''
def fuzzy_json(binary:str, injson:str) -> bool:
    cmd = f'./{binary}'

    # try empty file
    badjson = empty_file()
    ret = subprocess.run(cmd, input=badjson, stdout=subprocess.PIPE, text=True)
    detect_crash(ret, badjson)

    # try large value for each key. Key is not mutated
    badjson = bigint_value_json(injson)
    ret = subprocess.run(cmd, input=badjson, stdout=subprocess.PIPE, text=True)
    detect_crash(ret, badjson)

    # try large amount of key:value pairs
    badjson = bigkeys_json(injson, 100000)
    ret = subprocess.run(cmd, input=badjson, stdout=subprocess.PIPE, text=True)
    detect_crash(ret, badjson)

def fuzzy_plaintext():
    pass