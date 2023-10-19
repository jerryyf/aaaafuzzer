#!/usr/bin/python

from pwn import *
import sys
import bof
import fmtstr

N_ITER = 10 # set this to a larger number of iterations later or get input
LEN = 100

binary_name = sys.argv[1]
binary_input = sys.argv[2]

if __name__ == '__main__':

    LEN = input('Enter number of iterations: ')

    log.info('Trying overflows...')
    bof.overflow_stdin(binary_name, LEN, N_ITER)

    log.info('Trying cyclic inputs...')
    bof.cyclic_stdin(binary_name, LEN, N_ITER)

    log.info('Trying format string vulnerabilities...')
    fmtstr.find_fmtbuf_stdin(binary_name, N_ITER)

