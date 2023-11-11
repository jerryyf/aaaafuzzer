# aaaafuzzer
fuzzer for 32 bit binaries

## Functionality

- stdin fuzzing
    - buffer overflow detection
    - format string vulnerability detection
- file input fuzzing
    - file mutation based on a given file
        - csv and json (so far)
        - generates `bad.txt` when a crash is detected

## Overall design

- main fuzzer code in `fuzzer.py`
- main payload generation and fuzzer functions in `payloads.py`
    - `bad.txt` will be created only if a crash is detected
- helpers in `checkType.py` and `util.py`
- log files can be found at `/tmp/aaaalog`

## Detail Description (MIDPOINT):

The team mainly target on overflow vulnerabilities for the midpoint.
Initially, the original payload that we had was to use cyclic and attempting
to overflow the information space, and we trying that against JSON1 and CSV1.
However, that did work for JSON2 and CSV2 as we test our payloads againts these
two binaries.

### For JSON:

There are two types of vulnerabilities that we have considered for JSON input.
The first one is by exploiting the keys and their values. This is done by taking
the advantage of the cyclic command from gdb. We first take in the sameple input
and simply replace the keys and corresponding values with a large input generated
by cyclic, then parse the input into the binary.

An example sample input is the following:

`{"OUTPUT OF CYCLIC(3000)":"OUTPUT OF CYCLIC(3000)"}`

The second way is to modify the actual value in the json payload and hope that 
asks system for something that's not permitted and crashes the program.

An example sample input is the following:

`{"len":"99999999999"}`

### For CSV:

Just like JSON, at this stage the team has targeted for overflow. We have constructed
two different inputs.
The first is by expanding the size of the csv. This is vertically expansion or
horizontally expansion. Therefore, we have taken the csv sample input and just
stretched it.

An example sample input is the following:

`100 rows of [a,b]`

The second construction of payload is target at the specific value of the input file
with the CSV format. We will replace the specific value in the matrix with something
massive. 

An example sample input is the following:

`["a * 1000times", "b * 10000times"]`

