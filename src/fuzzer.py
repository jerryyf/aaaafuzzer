#!/usr/bin/python

from pwn import *
import sys
import bof
import time
import fmtstr
import multiprocessing
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from checkType import *
from fuzzer_csv import *

N_ITER = 10 # set this to a larger number of iterations later or get input
LEN = 100

if __name__ == '__main__':

    # Check valid input
    if len(sys.argv) != 3:
        print(f"Invalid input format! Usage: ./fuzzer binary input.txt")
        sys.exit(1)

    # If valid, then check given input file, extract
    try: 
        binary_input = open(sys.argv[2], 'r')
        # content = binary_input.read()

    except:
        print(f"Error: Cannot open .txt file")
        sys.exit(1)
        
    init_time = time.time()
    binary_file = sys.argv[1]

    if checkTypeJson(binary_input):
        log.info("going to assess binary as JSON")

    elif checkTypeCSV(binary_input):  
        fuzz_csv(binary_file, binary_input, 'bad.txt')
        log.info("going to assess binary as CSV")


    final_time = time.time()

    print(f"Fuzzer process done in {final_time - init_time} seconds...")


# Code for multiprocessing, keep for now
################################################################
# Record the time process start
#
# # Create a mission list
# mission = []
# lock = multiprocessing.Lock()

# # Assumed cpu number is 5, maybe need to change later to maximise performance
# executor = ThreadPoolExecutor()

# # For test purpose on multiprocessing, feel free to delete
# def JsonFuzzer(sampleInput, binary_file, lock):
#     print(f"sucess")
#
# # Usage: 
#     if checkTypeJson(binary_input):
#         print(f"going to assess binary as JSON")
#         mission.append(executor.submit(JsonFuzzer, binary_input, binary_file, lock))
#         print(f"mission[]: {mission}")