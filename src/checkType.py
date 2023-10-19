import json
import csv

"""
Helpers for fuzzer, checks if the type of given input is in JSON format

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


"""
Helpers for fuzzer, checks if the type of given input is in CSV format

Argument: sample_binary

Returns: True   - If the file type match
         False  - Otherwise
"""
def checkTypeCSV(sample_binary):

    # Read file content from begining, try load by CSV
    try:
        # csv.Sniffer().sniff(sample_binary)
        csv.DictReader(sample_binary)                       ### BUG it check non-csv as csv
        print(f"YES CSV")

    # If load fail, return false
    except csv.Error:
        return False
    
    return True


