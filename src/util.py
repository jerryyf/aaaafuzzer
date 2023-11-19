import sys
import time
import subprocess
import xml

def usage():
    '''
    Prints invalid input format message and exits
    '''
    print(f"Invalid input format! Usage: ./fuzzer binary input.txt")
    sys.exit(1)

def curr_time_taken(init_time) -> float:
    '''
    Return: Time difference between current time and recorded time
    '''
    return time.time() - init_time

def runfuzz(cmd, bad_input):
    '''
    Spawn a process that runs a fuzzer using bad_input

    Return: Check value of the process
    '''
    try:
        result = subprocess.run(cmd, input=bad_input, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        return result
    except subprocess.CalledProcessError as e:
        pass

def runfuzz_bin(cmd:str, bad_input:bytes):
    '''
    Wrapper for spawning process that takes binary input

    Return: Check value of the process
    '''
    return subprocess.run(cmd, input=bad_input, stdout=subprocess.PIPE)

def runfuzzsingleoption(cmd, bad_input):
    payload = ""
    for all in bad_input[0]:
        payload += f"{all}\n"
    

    for all in bad_input[1:]:
        payload += f"{all}"

    try:
        result = subprocess.run(cmd, input=payload, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        return result
    except subprocess.CalledProcessError as e:
        pass

def runfuzzoptions(cmd, bad_input, OPTION):
    

    try:
        # if menu num more than 1, fuzz for menu
        if OPTION == 1:
            input = "\n".join(bad_input[0]) 
            input += f"\n{bad_input[1]}\n"
            input_lines = sum(1 for char in input if char == '\n')
            if input_lines != len(bad_input):
                return False
            result = subprocess.run(cmd, input=input, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            return result

        input = "\n".join(bad_input[0])
        input += f"\n{bad_input[1]}\n"
        result = subprocess.run(cmd, input=input, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        return result
    
    except subprocess.CalledProcessError as e:
        pass
