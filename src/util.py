import sys
import time
import subprocess

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
    return subprocess.run(cmd, input=bad_input, stdout=subprocess.PIPE, text=True)