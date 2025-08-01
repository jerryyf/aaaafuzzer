from pwn import *
import logging
import copy
from harness import detect_crash
from util import *
from mutations import *
import xml.etree.ElementTree as ET

PAD = 'A'
path = {}

"""
path = {
    "1": (trivial; ret_number), #first_line(ret number) 
    "2": (0-9a-zA-Z; ret_number), #menu # compare list(path.keys())[-1 and -2's ret_number]
    "3":...
}

['trivial', '2']
for each in list:
runfuzz(cmd, each)
runfuzz(cmd, list)

"""
    
# config - debug level won't be logged
logging.basicConfig(filename='/tmp/aaaalog', level=logging.INFO, format='[%(levelname)s] %(asctime)s - %(name)s - %(message)s')

ITER = 200

def fuzz_rows(binary_file, binary_input, sample_file_str) -> int:
    '''
    Read the file from the beginning and runfuzz line by line

    Return: Check value of whether or not fuzzer caused a crash
    '''
    binary_input.seek(0)
    payload = binary_input.readline()

    for i in range(0, 100):
        badpayload = (payload * i * 100)
    
    cmdret = runfuzz(binary_file, badpayload)
    return detect_crash(cmdret, sample_file_str)

def fuzz_colns(binary_file, binary_input, sample_file_str):
    '''
    Read the file from the beginning, and fuzz column by column

    Return: Check value of whether or not fuzzer caused a crash
    '''
    binary_input.seek(0)
    lines = [line.rstrip() for line in binary_input]

    # create a list for values going to be modified
    payload = []
    for item in lines:
        first_row = item.strip().split(",")

        # try fuzzing first column
        for i in range(0, len(first_row)):
            first_row[i] = PAD * 15 

        # join the modified contents
        badline = ",".join(first_row)
        payload.append(badline + '\n')
    
    badpayload = "".join(payload)
    cmdret = runfuzz(binary_file, badpayload)
    return detect_crash(cmdret, sample_file_str)

def fuzz_add(binary_file, binary_input, sample_file_str):
    '''
    Read the file, mutliply the initial input

    Return: 0 if successful, other crash
    '''
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
    '''
    Read the file, fuzz rows, columns and increase input

    Return: Check value of whether or not fuzzer caused a crash
    '''
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
    Generate and run a JSON bad.txt against binary. Log, write the bad input to bad.txt 
    and exit if program exits with a non-zero status.

    Return: Check value of whether or not fuzzer caused a crash
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

    Return: Check value of whether or not fuzzer caused a crash
    '''
    cmd = f'{binary}'
    first_line = read_first_line(sample_input_path)

    with open(sample_input_path, 'r') as inf:
        content = inf.read()
        lines = inf.readlines()
        stripped_lines = []
        for i in range(len(lines)):
            stripped_lines += lines[i].strip()

    first_line = read_first_line(sample_input_path)
    cmdret = runfuzz(cmd, first_line)
    ret = detect_crash(cmdret, first_line)
    value = f"{ret}"
    path[1] = value
    
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

    # generate menu options
    letter_list = get_char_menu_list()
    option_list = get_num_menu_list()
    for each in letter_list:
        option_list.append(each)

    # working for multiple menu
    MANYMENU = 0
    options = []
    for each in option_list:
        check = 0
        inp = []
        inp.append(each)
        if check == 1:
            break
        # test nested menus
        for i in range(4):
            inp.append(each)
            for all in options:
                all[0] = inp

            for any in options:
                any[0] = inp
                payload = 'A'*10000
                cmdret = runfuzzsingleoption(cmd, any)
                ret = detect_crash(cmdret, payload)
                if ret < 0:
                    return ret

            res = runfuzzoptions(cmd, inp, 1)
            if res.returncode == 0:
                tmp = []

                tmp.append(inp)
                payload = PAD * 10000
                tmp.append(payload)
                testtmp = tmp
                testtmp.append("wtfwtf")
                testtmp.append("wtfwtf")


                nextres = runfuzzoptions(cmd, testtmp, 1)
                if nextres == False:
                    check = 1
                    inp.pop()
                    tmp.pop()
                    tmp.pop()

                    options.append(tmp)
                    skip = 1
                    break

                options.append(tmp)
                
                value = f"{ret}"
                break

            for each in options:
                each[0] = inp
            
            check = 1
            break
        for any in options:
            payload = 'A'*10000
            cmdret = runfuzzoptions(cmd, any, 0)
            ret = detect_crash(cmdret, payload)
            if ret < 0:
                return ret
        

    for each in options:
        index = 0

        while True:
            if ret < 0:
                break
            
            
            if not compare_path_ret(path):
                badtxt = []
                badtxt.append(each)

                cmdret = runfuzzoptions(cmd, badtxt[0], 0)
                ret = detect_crash(cmdret, payload)
                if ret < 0:
                    generate_number_keys_dictionary(path, ret)
                    log.info('Found vulnerability on fuzzing menu then large file!')
                    return ret


            if not compare_path_ret(path):
                badtxt = empty_str()
                cmdret = runfuzz(cmd, badtxt)
                ret = detect_crash(cmdret, badtxt)
                if ret < 0:
                    generate_number_keys_dictionary(path, ret)
                    log.info('Found vulnerability on empty file!')
                    return ret

            if not compare_path_ret(path):
                # try large file
                badtxt = PAD * 10000
                cmdret = runfuzz(cmd, badtxt)
                ret = detect_crash(cmdret, badtxt)
                if ret < 0:
                    generate_number_keys_dictionary(path, ret)
                    log.info('Found vulnerability on large file!')
                    return ret
            

            if not compare_path_ret(path):
                # try known ints
                known_ints = [-1, 0, 127, 256, 1024, 65536, MAX_INT-1, MAX_INT]
                for line in lines:
                    for i in known_ints:
                        badtxt = line + str(i)
                        cmdret = runfuzz(cmd, badtxt)
                        ret = detect_crash(cmdret, badtxt)
                        if ret < 0:
                            value = f"{badtxt}; {ret}"
                            generate_number_keys_dictionary(path, ret)
                            log.info('Found vulnerability on known ints!')
                            return ret

            if not compare_path_ret(path):
                # try repeating sample input
                badtxt = repeat_sample_input(content, 10)
                cmdret = runfuzz(cmd, badtxt)
                ret = detect_crash(cmdret, badtxt)
                if ret < 0:
                    value = f"{badtxt}; {ret}"
                    generate_number_keys_dictionary(path, ret)
                    log.info('Found vulnerability on repeated input!')
                    return ret

            if not compare_path_ret(path):
                # try bit flipping whole file
                badtxt = random_char_flip(content)
                for i in range(ITER):
                    badtxt = random_char_flip(badtxt)
                    cmdret = runfuzz(cmd, badtxt)
                    ret = detect_crash(cmdret, badtxt)
                    if ret < 0:
                        value = f"{badtxt}; {ret}"
                        generate_number_keys_dictionary(path, ret)
                        log.info('Found vulnerability on bit flips!')
                        return ret

            if not compare_path_ret(path):
                # try bit flipping each line
                for line in lines:
                    for i in range(len(line)):
                        badtxt = bit_flip(content, i)
                        cmdret = runfuzz(cmd, badtxt)
                        ret = detect_crash(cmdret, badtxt)
                        if ret < 0:
                            value = f"{badtxt}; {ret}"
                            generate_number_keys_dictionary(path, ret)
                            log.info('Found vulnerability on bit flips!')
                            return ret

            if not compare_path_ret(path):
                for line in lines:
                    bitflips = walking_bit_flip(line, 16) # First do 16 bit flips
                    for i in range(len(bitflips)):
                        # Assume the first line is password - TODO detect output change
                        badtxt = line + bitflips[i]

                        cmdret = runfuzz(cmd, badtxt)
                        ret = detect_crash(cmdret, badtxt)
                    if ret < 0:
                        value = f"{badtxt}; {ret}"
                        generate_number_keys_dictionary(path, ret)
                        log.info('Found vulnerability on bit flips!')
                        return ret

            # random mutations
            if not compare_path_ret(path):
                for i in range(ITER):
                    badtxt = random_char_flip(content)
                    cmdret = runfuzz(cmd, badtxt)
                    ret = detect_crash(cmdret, badtxt)
                    if ret < 0:
                        value = f"{badtxt}; {ret}"
                        generate_number_keys_dictionary(path, ret)
                        log.info('Crashed with random char flip!')
                        return ret

            # random strings
            if not compare_path_ret(path):
                for i in range(ITER):
                    badtxt = random_str()
                    cmdret = runfuzz(cmd, badtxt)
                    ret = detect_crash(cmdret, badtxt)
                    if ret < 0:
                        value = f"{badtxt}; {ret}"
                        generate_number_keys_dictionary(path, ret)
                        log.info('Crashed with random string!')
                        return ret

            # update sample line index
            index += 1
            if not read_index_line(index, sample_input_path):
                break

            nth_line = read_index_line(index, sample_input_path)
            cmdret = runfuzz(cmd, nth_line)
            ret = detect_crash(cmdret, nth_line)
            value = f"{nth_line}; {ret}"
            path[index + 1] = ret
        return ret

    '''
    Generate and run a XML bad.txt against binary. Log, write the bad input to bad.txt and exit if program exits with a non-zero status.

    Returns: the return code of the binary
    '''

def fuzz_child_tags(binary_file, sample_file_str, FUZZ_NUM) -> int:
    try:
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
    except ET.ParseError as e:
        pass

def fuzz_xml(binary_file, sample_file_str) -> int:
    try:
        cmd = f'{binary_file}'

        # try new line 
        badtxt = '\n'
        cmdret = runfuzz(cmd, badtxt)
        ret = detect_crash(cmdret, badtxt)
        if ret < 0:
            log.info(f"Found vulnerability on empty xml!...")
            return ret
        
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
        try:
            root = ET.fromstring(badtxt)
        except Exception as e:
            log.error(f"Error during XML parsing: {e}", exc_info=True)
            return -1

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
            badtxt = fuzz_attri_xml(sample_file_str, each)
            try:
                root = ET.fromstring(badtxt)
            except Exception as e:
                log.error(f"Error during XML parsing: {e}", exc_info=True)
                return -1
            cmdret = runfuzz(cmd, badtxt)
            ret = detect_crash(cmdret, badtxt)
            if ret < 0:
                log.info(f"Found vulnerability on fuzzing xml attributes!...")
                return ret

        return ret
    except Exception as e:
        log.error(f"Unexpected error during XML fuzzing: {e}", exc_info=True)
        return -1



def fuzz_jpg(binary:str, sample_input_path:str) -> int:
    '''
    Fuzz plaintext with mutated inputs.

    Return: Check value of whether or not fuzzer caused a crash
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
