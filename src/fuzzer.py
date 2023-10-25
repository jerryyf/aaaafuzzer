#!/usr/bin/python

from pwn import *
import sys
import bof
import time
import fmtstr
import multiprocessing
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from checkType import *

N_ITER = 10 # set this to a larger number of iterations later or get input
LEN = 100

# For test purpose on multiprocessing, feel free to delete
def JsonFuzzer(sampleInput, binary_file, lock):
    print(f"sucess")

if __name__ == '__main__':

    # Check valid input
    if len(sys.argv) != 3:
        print(f"Invalid input format! Usage: ./fuzzer binary input.txt")
        sys.exit(1)

    # IF valid, then check given input file, extract
    try: 
        binary_input = open(sys.argv[2], 'r')

    except:
        print(f"Error: Cannot open .txt file")
        sys.exit(1)

    binary_file = sys.argv[1]

    # Record the time process start
    init_time = time.time()

    # Create a mission list
    mission = []
    lock = multiprocessing.Lock()

    # Assumed cpu number is 5, maybe need to change later to maximise performance
    executor = ThreadPoolExecutor()

    if checkTypeJson(binary_input):
        print(f"going to assess binary as JSON")
        mission.append(executor.submit(JsonFuzzer, binary_input, binary_file, lock))

    if checkTypeCSV(binary_input):  
        print(f"going to assess binary as CSV")


    final_time = time.time()

    print(f"Fuzzer process done in {final_time - init_time} seconds...")

