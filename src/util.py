import sys
import time
import subprocess

def usage():
    print(f"Invalid input format! Usage: ./fuzzer binary input.txt")
    sys.exit(1)

def curr_time_taken(init_time) -> float:
    return time.time() - init_time

def runfuzz(cmd, bad_input):
    try:
        result = subprocess.run(cmd, input=bad_input, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        return result
    except subprocess.CalledProcessError as e:
        pass

def runfuzzoptions(cmd, bad_input, OPTION):
    
    try:
        # if menu num more than 1, fuzz for menu
        if OPTION == 1:
            input = "\n".join(bad_input[0]) 
            input += f"\n{bad_input[1]}\n"
            input_lines = sum(1 for char in input if char == '\n')
            if input_lines != len(bad_input):
                return False
            result = subprocess.run(cmd, input=input, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            return result

        print(bad_input[0])
        input = "\n".join(bad_input[0])
        input += f"\n{bad_input[1]}\n"
        print(f"input: {input}")
        result = subprocess.run(cmd, input=input, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        print(result)
        return result
    
    except subprocess.CalledProcessError as e:
        pass
