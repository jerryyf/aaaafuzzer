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

def fuzz_colns(binary_file, binary_input, target_output):
    binary_input.seek(0)
    # for i in range(1, len(binary_input.readlines()) + 1):
        # payload = binary_input.readline()
        # if not payload:
        #     break
        # print(f"payload: {payload}")
    lines = [line.rstrip() for line in binary_input]
    print(f"lines: {lines}")

    payload = []
    for item in lines:
        first_row = item.strip().split(",")
        # print(f"first row contents: {first_row}")

        # try fuzzing forst column
        for i in range(0, len(first_row)):
            first_row[i] = first_row[i]*999*10000
            # print(f"newrows: {first_row}")

        #join the modified contents
        badline = ",".join(first_row)
        # print(f"badline: {badline}")
        payload.append(badline + '\n')
    
    badpayload = "".join(payload)
    print(f"payload: {badpayload}")

    ret = subprocess.run(binary_file, input=badpayload, stdout=subprocess.PIPE, text=True)

    if ret.returncode != 0:
        log.critical('Crashed on fuzzing columns...')
        # outf.write(badjson)
        with open(target_output, 'a') as badcsv:
            badcsv.write(badpayload)



    # payload = binary_input.readline()
    # first_row = payload.strip().split(",")
    # print(f"first row contents: {first_row}")

    # # try fuzzing forst column
    # for i in range(0, len(first_row)):
    #     first_row[i] = first_row[i]*9999999999
    #     # print(f"1st thing: {first_row[i]}")

    # badpayload = ",".join(first_row)
    # print(f"send payload: {badpayload}")






def fuzz_csv(binary_file, binary_input, target_output):

    log.info(f"Binary input file content: {binary_input}")

    if fuzz_rows(binary_file, binary_input, target_output):
        log.info(f"Found vulnerability on fuzzing rows!...")

    if fuzz_colns(binary_file, binary_input, target_output):
        log.info(f"Found vulnerability on fuzzing columns!...")

