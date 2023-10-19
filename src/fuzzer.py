#!/usr/bin/python

from pwn import *
import sys
import bof
import fmtstr
from checkType import *

N_ITER = 10 # set this to a larger number of iterations later or get input
LEN = 100


if __name__ == '__main__':

    # Check valid input
    if len(sys.argv) != 3:
        print(f"Invalid input format! Usage: ./fuzzer binary input.txt")
        sys.exit(1)

    # IF valid, then check given input file, extract
    binary_name = sys.argv[1]
    try: 
        binary_input = open(sys.argv[2], 'r')
    except:
        print(f"Error: Cannot open .txt file")
        sys.exit(1)

    LEN = input('Enter number of iterations: ')


    if checkTypeJson(binary_input):
        print(f"going to assess binary as JSON")
    
    if checkTypeCSV(binary_input):
        print(f"going to assess binary as CSV")



    # log.info('Trying overflows...')
    # bof.overflow_stdin(binary_name, LEN, N_ITER)

    # log.info('Trying cyclic inputs...')
    # bof.cyclic_stdin(binary_name, LEN, N_ITER)

    # log.info('Trying format string vulnerabilities...')
    # fmtstr.find_fmtbuf_stdin(binary_name, N_ITER)

