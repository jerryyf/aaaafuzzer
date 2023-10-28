import json
import csv

"""
Helpers for fuzzer, checks if the type of given input is in JSON format

Argument: sample_binary

Returns: True   - If the file type match
         False  - Otherwise
"""
def checkTypeJson(sample_binary):
    sample_binary.seek(0)

    # Read file content from begining, try load by JSON
    try:
        json.load(sample_binary)
    # If load fail, return false
    except:
        print(f"Not JSON file...")
        return False
    
    return True



"""
Helpers for fuzzer, checks if the type of given input is in CSV format

Argument: sample_binary

Returns: True   - If the file type match
         False  - Otherwise
"""
def checkTypeCSV(sample_binary):
    sample_binary.seek(0)

    # Check type of input file by line and commas counting
    lines = sample_binary.readlines()

    commas = lines[0].count(",")

    # if file has one line only or no commas, return false
    if len(lines) == 1 or commas == 0:
        print(f"Not CSV file...")
        return False
    
    # compare comma numbers for each line, if not match then retuirn false
    for l in lines:
        if l.count(",") != commas:
            print(f"Not CSV file...")
            return False
    
    # type check passed, return true
    return True

    # some thinkings on csv exploid:
    # 1. overflow row, current error gave command not found cyclic at offset 4091 + 4 bytes 
    # 2. overflow colns
    # 3. send empty data