#!/usr/bin/python

from pwn import *
import sys
import time
from checkType import checkTypeCSV, checkTypeJson
from util import usage
from payloads import *
import multiprocessing
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from checkType import *
from fuzzer_csv import *

# number of processes to start
N_ITER = 10
# length of overflows, cyclics, etc.
LEN = 100

if __name__ == '__main__':

    # Check valid input
    if len(sys.argv) != 3:
        usage()

    # If valid, then check given input file, open for reading
    try: 
        sample_file = open(sys.argv[2], 'r')

    except:
        print(f"Error: Cannot open .txt file")
        usage()
        sys.exit(1)
        
    init_time = time.time()
    binary_file = sys.argv[1]
    sample_file_str = sys.argv[2]

    print(f'FUZZZZZZZZZZZZZZZZZZZZZZZZING...............')

    if checkTypeJson(sample_file):
        log.info("going to assess binary as JSON")
        fuzzy_json(binary_file, sample_file_str)
        sys.exit()
    
    elif checkTypeCSV(sample_file):  
        fuzz_csv(binary_file, sample_file, 'bad.txt')
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