import sys
import time
import subprocess

def usage():
    print(f"Invalid input format! Usage: ./fuzzer binary input.txt")
    sys.exit(1)

def curr_time_taken(init_time) -> float:
    return time.time() - init_time

def runfuzz(cmd:str, bad_input:str):
    return subprocess.run(cmd, input=bad_input, stdout=subprocess.PIPE, text=True)

def runfuzz_bin(cmd:str, bad_input:bytes):
    return subprocess.run(cmd, input=bad_input, stdout=subprocess.PIPE)
