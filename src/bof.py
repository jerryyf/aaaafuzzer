from pwn import *

def overflow_stdin(binary_name:str, len:int, iter:int):
    # try:
    for i in range(iter):
        try:
            print(f'AAAA {i}')
            io = process(f'./{binary_name}')
            io.sendline(b'A' * len)
            log.info(io.recvline())

        except Exception as e:
            logging.error(e)
            pass

def cyclic_stdin(binary_name:str, len: int, iter:int):
    for i in range(iter):
        try:
            print(f'cyclic {i}')
            io = process(f'./{binary_name}')
            io.sendline(cyclic(len))
            log.info(io.recvline())

        except Exception as e:
            logging.error(e)
            pass