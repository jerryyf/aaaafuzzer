import sys
import time
import subprocess

def usage():
    print(f"Invalid input format! Usage: ./fuzzer binary input.txt")
    sys.exit(1)

def curr_time_taken(init_time) -> float:
    return time.time() - init_time

# def runfuzz(cmd, bad_input):
#     return subprocess.run(cmd, input=bad_input, stdout=subprocess.PIPE, text=True)

def runfuzz(cmd, bad_input):
    try:
        result = subprocess.run(cmd, input=bad_input, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        return result
    except subprocess.CalledProcessError as e:
        pass