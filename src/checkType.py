import json
import csv

"""
Helpers for fuzzer, checks if the type of given binary is in JSON format

Argument: sample_binary

Returns: True   - If the file type match
         False  - Otherwise
"""
def checkTypeJson(sample_binary):

    # Read file content from begining, try load by JSON
    try:
        json.load(sample_binary)

    # If load fail, return false
    except:
        return False
    
    return True




# def checkTypeCSV():
#     # TODO