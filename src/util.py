import sys
import time
import subprocess

'''
Prints invalid input format message and exits
'''
def usage():
    print(f"Invalid input format! Usage: ./fuzzer binary input.txt")
    sys.exit(1)

'''
Return: Time difference between current time and recorded time
'''
def curr_time_taken(init_time) -> float:
    return time.time() - init_time

'''
Spawn a process that runs a fuzzer using bad_input

Return: Check value of the process
'''
def runfuzz(cmd, bad_input):
    return subprocess.run(cmd, input=bad_input, stdout=subprocess.PIPE, text=True)