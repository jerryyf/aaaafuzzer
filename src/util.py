import sys

def usage():
    if len(sys.argv) != 3:
        print(f"Invalid input format! Usage: ./fuzzer binary input.txt")
        sys.exit(1)