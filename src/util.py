import sys
import time

def usage():
    print(f"Invalid input format! Usage: ./fuzzer binary input.txt")
    sys.exit(1)

def curr_time_taken(init_time) -> float:
    return time.time() - init_time