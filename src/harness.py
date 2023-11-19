from pwn import *
import math
from subprocess import CompletedProcess
from util import curr_time_taken

MAX_RUNTIME = 160
stdouts = []

def detect_crash(proc:CompletedProcess[str], input:str) -> int:
    '''
    Given a completed process from subprocess.run() and the input given to the program,
    if exit with non-zero code, log the crash type and generate bad.txt

    Returns process return code.
    '''
    if proc.returncode < 0:
        logging.critical(f'Crashed with input {input}')
        log.critical(f'Program crashed, returned {proc.returncode}. Check /tmp/aaaalog for details. bad.txt generated in current directory.')
        with open('./bad.txt', 'w') as outf:
            outf.write(input)
    # in any case, add to list of outputs and log
    stdouts.append(proc.stdout)
    logging.info('Input tried:\n' + input)
    logging.info('Program output:\n' + proc.stdout)
    return proc.returncode

def max_runtime_kill(curr_time) -> bool:
    '''
    Takes in current time taken; if greater than MAX_RUNTIME exit the program.
    '''
    if curr_time_taken(curr_time) >= MAX_RUNTIME:
        log.info('Max runtime exceeded. Exiting.')
        sys.exit()

def detect_codeflow_change_json(binary:str, jsondict:dict):
    '''
    Takes in a binaryfile and detects if there were any codeflow changes
    '''
    payload = []
    ret_status = []
    cmd = f'{binary}'
    cycle = 0
    while (cycle <= 2):
        cyclic_int = int(math.pow(10, cycle))
        
        single_Payload = f"{cyclic_int}: cylic({cyclic_int})"

        payload.append(single_Payload)
        
        cyclic_str = cyclic(cyclic_int, alphabet = string.ascii_lowercase)
        
        for k in jsondict:
            jsondict[k] = cyclic_str
        badjson = str(jsondict).replace("'",'"')
        ret = subprocess.run(cmd, input=badjson, stdout=subprocess.PIPE, text=True)
        
        if ret.returncode != 0:
            log.critical(f'Crashed on cyclic({cyclic_int})')
        out = ret.stdout
        log.info(out)
        ret_status.append(out)
        
        if (cycle == 1): 
            cycle += 1
            continue
        
        previous_int = int(math.pow(10, cycle - 1))
        previous_str = cyclic(previous_int, alphabet = string.ascii_lowercase)
        
        prev_Ret = ret_status[cycle - 1].replace(previous_str, " ")
        
        curr_Ret = ret_status[cycle].replace(cyclic_str, " ")
            
        if prev_Ret != curr_Ret:
            print(f"Changed return status at {cycle}")
            prev_Cyc = cyclic_int
            curr_Cyc = int(math.pow(10, cycle - 1))
            log.info(f'code flow changed - {cycle - 1} -> {cycle}')
            break
        
        cycle += 1
