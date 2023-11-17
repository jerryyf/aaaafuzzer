from pwn import *
import logging
import copy
from harness import detect_crash
from util import *
from mutations import *
import xml.etree.ElementTree as ET

PAD = 'A'

# config - debug level won't be logged
logging.basicConfig(filename='/tmp/aaaalog', level=logging.INFO, format='[%(levelname)s] %(asctime)s - %(name)s - %(message)s')

# TODO refactor csv

def fuzz_rows(binary_file, binary_input, sample_file_str) -> int:
    # read file from beginning
    binary_input.seek(0)
    payload = binary_input.readline()

    for i in range(0, 100):
        badpayload = (payload * i * 100)

    cmdret = runfuzz(binary_file, badpayload)
    ret = detect_crash(cmdret, sample_file_str)
    return ret

def fuzz_colns(binary_file, binary_input, sample_file_str):
    # read file from begining
    binary_input.seek(0)
    lines = [line.rstrip() for line in binary_input]

    # create a list for values going to be modified
    payload = []
    for item in lines:
        first_row = item.strip().split(",")

        # try fuzzing first column
        for i in range(0, len(first_row)):
            first_row[i] = PAD * 15 # TODO not working with larger ints - not black box

        # join the modified contents
        badline = ",".join(first_row)
        payload.append(badline + '\n')
    
    badpayload = "".join(payload)
    cmdret = runfuzz(binary_file, badpayload)
    return detect_crash(cmdret, sample_file_str)


def fuzz_csv(binary_file, binary_input, sample_file_str) -> int:
    ret = fuzz_rows(binary_file, binary_input, sample_file_str)
    if ret:
        log.info(f"Found vulnerability on fuzzing rows!...")
        return ret

    ret = fuzz_colns(binary_file, binary_input, sample_file_str)
    if ret:
        log.info(f"Found vulnerability on fuzzing columns!...")
        return ret
    return ret


'''
Generate and run a JSON bad.txt against binary. Log, write the bad input to bad.txt and exit if program exits with a non-zero status.

Returns: the return code of the binary
'''
def fuzz_json(binary:str, injson:str) -> bool:
    cmd = f'./{binary}'

    # try empty file
    badjson = empty_str()
    cmdret = runfuzz(cmd, badjson)
    ret = detect_crash(cmdret, badjson)
    if ret:
        return ret

    # try large value for each key. Key is not mutated
    badjson = bigint_value_json(injson)
    cmdret = runfuzz(cmd, badjson)
    ret = detect_crash(cmdret, badjson)
    if ret:
        return ret

    # try large amount of key:value pairs
    badjson = bigkeys_json(injson, 100000)
    cmdret = runfuzz(cmd, badjson)
    ret = detect_crash(cmdret, badjson)
    if ret:
        return ret
    return ret

'''
Fuzz plaintext with mutated inputs.

Returns: return code of binary
'''
def fuzz_plaintext(binary:str, intxt:str) -> int:
    cmd = f'./{binary}'

    # try empty file
    badtxt = empty_str()
    cmdret = runfuzz(cmd, badtxt)
    ret = detect_crash(cmdret, badtxt)
    if ret != 0:
        return ret

    # try large file
    badtxt = PAD * 10000
    cmdret = runfuzz(cmd, badtxt)
    ret = detect_crash(cmdret, badtxt)
    if ret:
        return ret

    # try mutations on the file
    badtxt = repeat_sample_input(intxt, 20)
    cmdret = runfuzz(cmd, badtxt)
    ret = detect_crash(cmdret, badtxt)
    if ret:
        return ret
    return ret


'''
Generate and run a XML bad.txt against binary. Log, write the bad input to bad.txt and exit if program exits with a non-zero status.

Returns: the return code of the binary
'''
def fuzz_child_tags(binary_file, sample_file_str, FUZZ_NUM) -> int:
    cmd = f'./{binary_file}'
    # read file from beginning
    with open(sample_file_str, 'r') as f:
        f.seek(0)
        payload = f.read()
    # grab the root element from payload and copy all subchild 
    root = ET.fromstring(payload)
    head = copy.deepcopy(root)
    # append child elements into payload
    for i in range(FUZZ_NUM):
        tail = copy.deepcopy(head)
        root.append(tail)
        bad = ET.tostring(root).decode()
        cmdret = runfuzz(cmd, bad)
        ret = detect_crash(cmdret, bad)
        if ret:
            return ret
    return ret


def fuzz_xml(binary_file, sample_file_str) -> int:
    cmd = f'./{binary_file}'

    # try empty xml 
    badtxt = empty_xml()
    cmdret = runfuzz(cmd, badtxt)
    ret = detect_crash(cmdret, badtxt)
    if ret:
        log.info(f"Found vulnerability on empty xml!...")

    # try nested xml tags
    badtxt = nested_tags_xml()
    cmdret = runfuzz(cmd, badtxt)
    ret = detect_crash(cmdret, badtxt)
    if ret:
        log.info(f"Found vulnerability on nested xml tags!...")

    # try tested xml contents
    badtxt = generate_nested_contents(sample_file_str)
    cmdret = runfuzz(cmd, badtxt)
    ret = detect_crash(cmdret, badtxt)
    if ret:
        log.info(f"Found vulnerability on nested content xml!...")

    # try fuzz child tags
    ret = fuzz_child_tags(binary_file, sample_file_str, 100)
    if ret:
        log.info(f"Found vulnerability on fuzzing child xml tags!...")

    # try fuzz xml attributes
    form_string_chars = ['%s', '%d', '%p', '%x', '$', '<', PAD*100]
    for each in form_string_chars:
        badtxt =  fuzz_attri_xml(sample_file_str, each)
        cmdret = runfuzz(cmd, badtxt)
        ret = detect_crash(cmdret, badtxt)
        if ret:
            log.info(f"Found vulnerability on fuzzing xml attributes!...")

    return ret
    
