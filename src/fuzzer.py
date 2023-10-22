#!/usr/bin/python

from pwn import *
import sys
import time
from checkType import checkTypeCSV, checkTypeJson
from util import usage
from payloads import *

# number of processes to start
N_ITER = 10

# length of overflows, cyclics, etc.
LEN = 100


if __name__ == '__main__':

    # Check valid input
    usage()

    # IF valid, then check given input file, extract
    binaryfile = sys.argv[1]
    samplefile = sys.argv[2]

    # Record the time process start
    init_time = time.time()

    if checkTypeJson(samplefile):
        log.info("going to assess binary as JSON")
        fuzzy_json(binaryfile, samplefile, 'bad.txt')
        sys.exit()
    
    if checkTypeCSV(samplefile):  
        log.info("going to assess binary as CSV")
        sys.exit()
    
    final_time = time.time()

    print(f"Fuzzer process done in {final_time - init_time} seconds...")