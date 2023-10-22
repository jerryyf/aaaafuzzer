#!/usr/bin/python

from pwn import *
import subprocess
import sys

N_ITER = 10 # set this to a larger number of iterations later
binary_name = sys.argv[1]
binary_input = sys.argv[2]

bad_csv = f'header,must,stay,intact\n%p,%p,%p,%p\n{cyclic(200)},{cyclic(300)},{cyclic(400)},{cyclic(500)}'
bad_json = '{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA": "%p"}'


try:
    log.info('Trying overflows...')
    for i in range(N_ITER):
        p = process(f'./{binary_name}')
        p.sendline(b'A' * 200)
        log.info(p.recvline())

except:
    log.critical(error)

try:
    log.info('Trying format string vulnerabilities...')
    for i in range(N_ITER):
        p = process(f'./{binary_name}')
        p.sendline(b'%p')
        log.info(p.recvline())
except:
    log.critical(error)

try:
    log.info('Trying fuzzed csv inputs...')
    for i in range(N_ITER):
        subprocess.run(f'echo {bad_csv} >> {binary_input}')
        p = process(f'./{binary_name} {binary_input}')
        log.info(p.recvline())
except:
    log.critical(error)

try:
    log.info('Trying fuzzed json inputs...')
    for i in range(N_ITER):
        subprocess.run(f'echo {bad_json} >> {binary_input}')
        p = process(f'./{binary_name} {binary_input}')
        log.info(p.recvline())
except:
    log.critical(error)