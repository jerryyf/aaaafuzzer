import csv
import sys
import os
from pwn import *


def fuzz_rows(binary_file, binary_input, target_output):
    binary_input.seek(0)
    payload = binary_input.readline()
    print(f"payload: {payload}")

    for i in range(0, 100):
        badpayload = (payload * i * 100)
        # print(f"input: {badpayload}")

    ret = subprocess.run(binary_file, input=badpayload, stdout=subprocess.PIPE, text=True)

    if ret.returncode != 0:
        log.critical('Crashed on fuzzing rows...')
        # outf.write(badjson)
        with open(target_output, 'a') as badcsv:
            badcsv.write(badpayload)






def fuzz_csv(binary_file, binary_input, target_output):

    log.info(f"Binary input file content: {binary_input}")

    if fuzz_rows(binary_file, binary_input, target_output):
        log.info(f"Found vulnerability!...")

    

