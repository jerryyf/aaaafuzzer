from pwn import *
import json
import subprocess
import logging

MAX_INT = sys.maxsize
LARGE_CHAR = cyclic(10000)

# config - debug level won't be logged
logging.basicConfig(filename='/tmp/aaaalog.log', level=logging.INFO, format='[%(levelname)s] %(asctime)s - %(name)s - %(message)s')


def fuzzy_csv(binary:str, incsv:str, outjson:str):
    # TODO
    bad_csv = f'header,must,stay,intact\n%p,%p,%p,%p\n{cyclic(100)},{cyclic(200)},{cyclic(300)},{cyclic(400)}'
    with open(incsv, 'w') as f:
        f.write(bad_csv)

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
        logging.info('JSON file input: ' + str(jsondict))
        for k in jsondict:
            if type(jsondict[k]) == int:
                jsondict[k] = MAX_INT
    return str(jsondict).replace("'",'"')

def bigstr_value_json(injson:str, power:int) -> str:
    cycle = 1
    with open(injson, 'r') as inf:
        jsondict = json.load(inf)
        logging.info('JSON sample input: ' + str(jsondict))

    while (cycle <= power):
        cyclic_int = int(math.pow(10, cycle))
        cyclic_str = cyclic(cyclic_int, alphabet=string.ascii_lowercase)

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
def fuzzy_json(binary:str, injson:str, outjson:str) -> bool:
    stdouts = []
    cmd = f'./{binary}'
    context.cyclic_alphabet = string.ascii_lowercase
        
    # try empty file
    badjson = empty_file()
    ret = subprocess.run(cmd, input=badjson, stdout=subprocess.PIPE, text=True)
    if ret.returncode != 0:
        log.critical(f'Crashed on empty file - program returned {ret.returncode}')
        with open(outjson, 'w') as outf:
            outf.write(badjson)
    # in any case, add to list of outputs and log
    stdouts.append(ret.stdout)
    logging.info('json empty file program output:\n' + ret.stdout)

            
    # try large value for each key. Key is not mutated
    badjson = bigint_value_json(injson)
    ret = subprocess.run(cmd, input=badjson, stdout=subprocess.PIPE, text=True)
    if ret.returncode != 0:
        log.critical(f'Crashed on large int value - program returned {ret.returncode}')
        with open(outjson, 'w') as outf:
            outf.write(badjson)
    # in any case, add to list of outputs and log
    stdouts.append(ret.stdout)
    logging.info('json large value program output:\n' + ret.stdout)
    
    # try large amount of key:value pairs
    badjson = bigkeys_json(injson, 100000)
    ret = subprocess.run(cmd, input=badjson, stdout=subprocess.PIPE, text=True)
    if ret.returncode != 0:
        log.critical(f'Crashed on large amount of key value pairs - program returned {ret.returncode}')
        with open(outjson, 'w') as outf:
            outf.write(badjson)
    # in any case, add to list of outputs and log
    stdouts.append(ret.stdout)
    logging.info('json large key value pair program output:\n' + ret.stdout)

