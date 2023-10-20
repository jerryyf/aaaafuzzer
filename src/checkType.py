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
    jsonfile = open(sample_binary, 'r')
    try:
        json.load(jsonfile)
        print(f"The txt is in JSON format...")
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
    csvfile = open(sample_binary, 'r')

    try:
        data = csv.reader(csvfile, delimiter=',') # NOTE assumption that all csv files parsed are delimted with commas
        for row in data:
            if len(row) <= 1:                     # NOTE assumption that csv file contains more than 1 column
                print('Not a CSV')
                return False
        csvfile.seek(0)

    except:
    # If load fail, return false
        return False
        
    return True
