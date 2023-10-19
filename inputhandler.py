from pwn import *

# TODO handle input files for binaries

bad_csv = f'header,must,stay,intact\n%p,%p,%p,%p\n{cyclic(100)},{cyclic(200)},{cyclic(300)},{cyclic(400)}'
bad_json = '{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA": "%p"}'

def fuzzy_csv(fname:str):
    with open(fname, 'w') as f:
        f.write(bad_csv)

def fuzzy_json(fname:str):
    with open(fname, 'w') as f:
        f.write(bad_json)