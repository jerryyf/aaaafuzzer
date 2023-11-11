import csv
import sys
import os
from pwn import *

PAD = "A"

def fuzz_rows(binary_file, binary_input, target_output):
    binary_input.seek(0)
    payload = binary_input.readline()

    for i in range(0, 100):
        badpayload = (payload * i * 100)

    ret = subprocess.run(binary_file, input=badpayload, stdout=subprocess.PIPE, text=True)

    if ret.returncode != 0:
        log.critical(f"Program crashed, returned {ret.returncode}. Check /tmp/aaaalog for details. bad.txt generated at /tmp/bad.txt")
        # outf.write(badjson)
        with open(target_output, 'a') as badcsv:
            badcsv.write(badpayload)


def fuzz_colns(binary_file, binary_input, target_output):
    # read file from begining
    binary_input.seek(0)
    lines = [line.rstrip() for line in binary_input]

    # create a list for values going to be modified
    payload = []
    for item in lines:
        first_row = item.strip().split(",")

        # try fuzzing forst column
        for i in range(0, len(first_row)):
            first_row[i] = PAD*15

        # join the modified contents
        badline = ",".join(first_row)
        payload.append(badline + '\n')
    
    badpayload = "".join(payload)

    ret = subprocess.run(binary_file, input=badpayload, stdout=subprocess.PIPE, text=True)

    if ret.returncode != 0:
        log.critical(f"Program crashed, returned {ret.returncode}. Check /tmp/aaaalog for details. bad.txt generated at /tmp/bad.txt")
        with open(target_output, 'a') as badcsv:
            badcsv.write(badpayload)


def fuzz_csv(binary_file, binary_input, target_output):

    if fuzz_rows(binary_file, binary_input, target_output):
        log.info(f"Found vulnerability on fuzzing rows!...")

    if fuzz_colns(binary_file, binary_input, target_output):
        log.info(f"Found vulnerability on fuzzing columns!...")

