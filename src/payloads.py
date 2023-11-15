from pwn import *
import logging
from harness import detect_crash
from util import *
from mutations import *

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


def fuzz_json(binary:str, injson:str) -> bool:
    '''
    Generate and run a JSON bad.txt against binary. Log, write the bad input to bad.txt and exit if program exits with a non-zero status.

    Returns: the return code of the binary
    '''
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

def fuzz_plaintext(binary:str, intxt:str) -> int:
    '''
    Fuzz plaintext with mutated inputs.

    Returns: return code of binary
    '''
    cmd = f'./{binary}'

    try:
        with open(intxt, 'r') as inf:
            lines = inf.readlines()
            stripped_lines = []
            for i in range(len(lines)):
                stripped_lines += lines[i].strip()
    except:
        log.warn('Failed reading plaintext lines, skipping.')

    # try empty file
    badtxt = empty_str()
    cmdret = runfuzz(cmd, badtxt)
    ret = detect_crash(cmdret, badtxt)
    if ret:
        return ret

    # try large file
    badtxt = PAD * 10000
    cmdret = runfuzz(cmd, badtxt)
    ret = detect_crash(cmdret, badtxt)
    if ret:
        return ret
    
    # try known ints
    known_ints = [-1, 0, 256, 1024, MAX_INT-1, MAX_INT]
    for line in lines:
        for i in known_ints:
            badtxt = line + str(i)
            cmdret = runfuzz(cmd, badtxt)
            ret = detect_crash(cmdret, badtxt)
            if ret:
                return ret

    # try repeating sample input
    badtxt = repeat_sample_input(intxt, 20)
    cmdret = runfuzz(cmd, badtxt)
    ret = detect_crash(cmdret, badtxt)
    if ret:
        return ret

    # try bit flipping whole file
    for i in range(len(intxt)): 
        badtxt = bit_flip(intxt, i)
        cmdret = runfuzz(cmd, badtxt)
        ret = detect_crash(cmdret, badtxt)
        if ret:
            return ret

    # try bit flipping each line
    for line in lines:
        for i in range(len(line)):
            badtxt = bit_flip(intxt, i)
            cmdret = runfuzz(cmd, badtxt)
            ret = detect_crash(cmdret, badtxt)
            if ret:
                return ret

    for line in lines:
        bitflips = walking_bit_flip(line, 16) # First do 16 bit flips
        for i in range(len(bitflips)):
            # Assume the first line is password - TODO detect output change
            badtxt = line + bitflips[i]

            cmdret = runfuzz(cmd, badtxt)
            ret = detect_crash(cmdret, badtxt)
        if ret:
            return ret

    return ret