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

ITER = 200

def fuzz_rows(binary_file, binary_input, sample_file_str) -> int:
    # read file from beginning
    binary_input.seek(0)
    payload = binary_input.readline()

    for i in range(0, 100):
        badpayload = (payload * i * 100)

    cmdret = runfuzz(binary_file, badpayload)
    return detect_crash(cmdret, sample_file_str)

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

def fuzz_add(binary_file, binary_input, sample_file_str):
    binary_input.seek(0)
    payload = binary_input.readline().strip()

    for i in range(1, 100):
        # Repeat the initial payload 'i' times
        badpayload = ','.join([payload] * i)
    
    cmdret = runfuzz(binary_file, badpayload)
    ret = detect_crash(cmdret, sample_file_str)
    if ret != 0:
        return ret  # Exit early if crash is detected
    return 0
    
def fuzz_csv(binary_file, binary_input, sample_file_str) -> int:
    ret = fuzz_rows(binary_file, binary_input, sample_file_str)
    if ret < 0:
        log.info(f"Found vulnerability on fuzzing rows!...")
        return ret

    ret = fuzz_colns(binary_file, binary_input, sample_file_str)
    if ret < 0:
        log.info(f"Found vulnerability on fuzzing columns!...")
        return ret
        
    ret = fuzz_add(binary_file, binary_input, sample_file_str)
    if ret:
        log.info(f"Found vulnerability on fuzzing columns!...")
        return ret
    return ret


def fuzz_json(binary:str, sample_input_path:str) -> bool:
    '''
    Generate and run a JSON bad.txt against binary. Log, write the bad input to bad.txt and exit if program exits with a non-zero status.

    Returns: the return code of the binary
    '''
    cmd = f'{binary}'

    with open(sample_input_path, 'r') as inf:
        content = json.load(inf)
        logging.info('JSON sample input: ' + str(content))

    # try empty file
    badjson = empty_str()
    cmdret = runfuzz(cmd, badjson)
    ret = detect_crash(cmdret, badjson)
    if ret < 0:
        log.info('Found vulnerability on empty file!')
        return ret
    
    # try large file
    badjson = PAD * 10000
    cmdret = runfuzz(cmd, badjson)
    ret = detect_crash(cmdret, badjson)
    if ret < 0:
        log.info('Found vulnerability on large file!')
        return ret

    # try large value for each key. Key is not mutated
    badjson = bigint_value_json(content)
    cmdret = runfuzz(cmd, badjson)
    ret = detect_crash(cmdret, badjson)
    if ret < 0:
        log.info('Found vulnerability on large json keys!')
        return ret

    # try large amount of key:value pairs
    badjson = bigkeys_json(content, 100000)
    cmdret = runfuzz(cmd, badjson)
    ret = detect_crash(cmdret, badjson)
    if ret < 0:
        log.info('Found vulnerability on large json keys!')
        return ret

    # in any case return status code
    return ret

def fuzz_plaintext(binary:str, sample_input_path:str) -> int:
    '''
    Fuzz plaintext with mutated inputs.

    Returns: return code of binary
    '''
    cmd = f'{binary}'

    with open(sample_input_path, 'r') as inf:
        content = inf.read()
        lines = inf.readlines()
        stripped_lines = []
        for i in range(len(lines)):
            stripped_lines += lines[i].strip()

    # try empty file
    badtxt = empty_str()
    cmdret = runfuzz(cmd, badtxt)
    ret = detect_crash(cmdret, badtxt)
    if ret < 0:
        log.info('Found vulnerability on empty file!')
        return ret

    # try large file
    badtxt = PAD * 10000
    cmdret = runfuzz(cmd, badtxt)
    ret = detect_crash(cmdret, badtxt)
    if ret < 0:
        log.info('Found vulnerability on large file!')
        return ret
    
    # try known ints
    known_ints = [-1, 0, 127, 256, 1024, 65536, MAX_INT-1, MAX_INT]
    for line in lines:
        for i in known_ints:
            badtxt = line + str(i)
            cmdret = runfuzz(cmd, badtxt)
            ret = detect_crash(cmdret, badtxt)
            if ret < 0:
                log.info('Found vulnerability on known ints!')
                return ret

    # try repeating sample input
    badtxt = repeat_sample_input(content, 10)
    cmdret = runfuzz(cmd, badtxt)
    ret = detect_crash(cmdret, badtxt)
    if ret < 0:
        log.info('Found vulnerability on repeated input!')
        return ret

    # try bit flipping whole file, mutating ITER amount of times
    badtxt = content
    for i in range(ITER):
        badtxt = random_char_flip(badtxt)
        cmdret = runfuzz(cmd, badtxt)
        ret = detect_crash(cmdret, badtxt)
        if ret < 0:
            log.info('Found vulnerability on bit flips!')
            return ret

    # try bit flipping each line, constantly mutating ITER amount of times
    badtxt = content
    for line in lines:
        for i in range(ITER):
            badtxt = random_char_flip(badtxt)
            cmdret = runfuzz(cmd, badtxt)
            ret = detect_crash(cmdret, badtxt)
            if ret < 0:
                log.info('Found vulnerability on bit flips!')
                return ret

    for line in lines:
        bitflips = walking_bit_flip(line, 16) # First do 16 bit flips
        for i in range(len(bitflips)):
            # Assume the first line is password - TODO detect output change
            badtxt = line + bitflips[i]

            cmdret = runfuzz(cmd, badtxt)
            ret = detect_crash(cmdret, badtxt)
        if ret < 0:
            log.info('Found vulnerability on bit flips!')
            return ret

    # random mutations
    for i in range(ITER):
        badtxt = random_char_flip(content)
        cmdret = runfuzz(cmd, badtxt)
        ret = detect_crash(cmdret, badtxt)
        if ret < 0:
            log.info('Crashed with random char flip!')
            return ret

    # random strings
    for i in range(ITER):
        badtxt = random_str()
        cmdret = runfuzz(cmd, badtxt)
        ret = detect_crash(cmdret, badtxt)
        if ret < 0:
            log.info('Crashed with random string!')
            return ret

    # return status would be 0 here
    return ret


'''
Generate and run a XML bad.txt against binary. Log, write the bad input to bad.txt and exit if program exits with a non-zero status.

Returns: the return code of the binary
'''
def fuzz_child_tags(binary_file, sample_file_str, FUZZ_NUM) -> int:
    cmd = f'{binary_file}'
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
        if ret < 0:
            return ret

    return ret


def fuzz_xml(binary_file, sample_file_str) -> int:
    cmd = f'{binary_file}'

    # try empty xml 
    badtxt = empty_xml()
    cmdret = runfuzz(cmd, badtxt)
    ret = detect_crash(cmdret, badtxt)
    if ret < 0:
        log.info(f"Found vulnerability on empty xml!...")
        return ret

    # try nested xml tags
    badtxt = nested_tags_xml()
    cmdret = runfuzz(cmd, badtxt)
    ret = detect_crash(cmdret, badtxt)
    if ret < 0:
        log.info(f"Found vulnerability on nested xml tags!...")
        return ret

    # try tested xml contents
    badtxt = generate_nested_contents(sample_file_str)
    cmdret = runfuzz(cmd, badtxt)
    ret = detect_crash(cmdret, badtxt)
    if ret < 0:
        log.info(f"Found vulnerability on nested content xml!...")
        return ret

    # try fuzz child tags
    ret = fuzz_child_tags(binary_file, sample_file_str, 100)
    if ret < 0:
        log.info(f"Found vulnerability on fuzzing child xml tags!...")
        return ret

    # try fuzz xml attributes
    form_string_chars = ['%s', '%d', '%p', '%x', '$', '<', PAD*100]
    for each in form_string_chars:
        badtxt =  fuzz_attri_xml(sample_file_str, each)
        cmdret = runfuzz(cmd, badtxt)
        ret = detect_crash(cmdret, badtxt)
        if ret < 0:
            log.info(f"Found vulnerability on fuzzing xml attributes!...")
            return ret

    return ret

def fuzz_jpg(binary:str, sample_input_path:str) -> int:
    '''
    Fuzz plaintext with mutated inputs.

    Returns: return code of binary
    '''
    cmd = f'{binary}'

    content = read(sample_input_path)

    # try empty file
    badjpg = empty_str()
    cmdret = runfuzz(cmd, badjpg)
    ret = detect_crash(cmdret, badjpg)
    if ret < 0:
        log.info('Found vulnerability on empty file!')
        return ret

    # try large file
    badjpg = PAD * 10000
    cmdret = runfuzz(cmd, badjpg)
    ret = detect_crash(cmdret, badjpg)
    if ret < 0:
        log.info('Found vulnerability on large file!')
        return ret
    
    # try mutating file header randomly
    badjpg = content
    print(bytes(bytearray(badjpg)[:4]))
    for i in range(ITER):
        byte = mutate_file_header(badjpg)
        # print(bytearray(badjpg[:4]))
        cmdret = runfuzz_bin(cmd, byte)
        ret = detect_crash(cmdret, byte)
        if ret < 0:
            return ret

    # return status would be 0 here
    return ret
