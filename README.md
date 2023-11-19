# aaaafuzzer

a fuzzer for 32 bit ELF binaries

## Overall design

- main fuzzer code in `fuzzer.py`
- main payload generation and fuzzer functions in `payloads.py`
    - `bad.txt` will be created only if a crash is detected
- mutation strategies in `mutations.py`
- helpers in `checkType.py` and `util.py`
- log files can be found at `/tmp/aaaalog`

## Scope

The main vulnerability the fuzzer target are memory corruption leading to segmentation faults, a vulnerability that could lead to exploits such as controlling the program via a shell. 

## How it works

The fuzzer works by sending in various mutated inputs in order to find a memory corruption bug. Our team has developed upon various mutation strategies that prevalent in modern day fuzzers in order to achieve this goal. When a crash is detected, a file called `bad.txt` is generated containing the input that will crash the program being fuzzed.

## Dependencies and libraries

- `file` is used to check the type of given input file.
- `pwntools` is used for pattern generation as well as byte IO.
- Standard python libaries used:
    - json
    - xml
    - copy
    - logging
    - random
    - sys
    - time
    - math
    - subprocess

## Mutation strategies

- Empty input: try no input.
- Large input: try large input of MAX_INT number of bytes.
- Repeating sample input: Taking the content of a given file and repeating the content to a certain number of iterations, as set by a global variable.
- Bit flips: essentially two different kind of implementations:
   - a *walking bit flip* in which bits of a given input are sequentially flipped, from least significant bit upwards.
   - a *random char flip* in which individual bits in a given input are flipped randomly, at random positions leading to random characters being replaced. This is used in conjunction with loops to recursively mutate a given input.
- Random strings: generates random string of default length 100. This can be adjusted to fit the use case and what type of program is being fuzzed
- Known integers: we try known integers that could lead to overflows or other errors, such as 256, -1, MAX_INT.
- CSV specific mutations:
   - mutating input rows with large values
   - mutating input columns with large values
- JSON specific mutations:
   - mutating all keys
   - mutating all values
- XML specific mutations:
    - newline
    - empty XML file
    - large number of child tags
    - large content in tags

## Harness capabilities

- Able to detect crashes and the type of crash that occurs when an bad input is given.
- Checks if there are infinite while loops by keeping track of the fuzzer runtime. If the time goes over a certain threshold, it will exit the program.
- simple code coverage to improve efficiency of the fuzzer. 
    - Works by keeping track of stdout from the program and checking whether it differs from the previous output. This results in going down multiple paths.
    - It first tries to crash the input buffer that is in the end of the longest path, and works its way backwards, attempting to crash the previous code path until the original code path.

## Fuzzing of different file formats

### JSON

There are two types of vulnerabilities that we have considered for JSON input.
The first one is by exploiting the keys and their values. This is done by taking
the advantage of the cyclic command from gdb. We first take in the sample input
and simply replace the keys and corresponding values with a large input generated
by cyclic, then parse the input into the binary.

An example sample input is the following:

`{"OUTPUT OF CYCLIC(3000)":"OUTPUT OF CYCLIC(3000)"}`

The second way is to modify the actual value in the json payload and hope that 
asks system for something that's not permitted and crashes the program.

An example sample input is the following:

`{"len":"99999999999"}`

### CSV

The fuzzer construct two different mutations. One is based on expanding the CSV input:
    - Vertical expansion (rows)
    - Horizontally expansion (columns)

An example sample input is the following:

`100 rows of [a,b]`

The second construction of payload is target at the specific value of the input file with the CSV format. It replaces the specific value in the matrix with a large number of bytes. 

An example sample input is the following:

`["a" * 1000, "b" * 10000]`

### Plaintext

Uses mutation strategies:

- Empty file
- Large file
- Repeated sample input
- Walking bit flips
- Recursive random bit flips
- Random strings

### XML

The fuzzer tests XML programs for unexpected input such as

- empty file,
- fuzzing xml tags,
- child tags,
- xml content.

Additionally, fuzzer is also run on xml atrributes and also checks for format string vulnerabilities. Through changing the values of tags and attributes, memory corruption vulnerabilities can be detected.

An example sample input is the following:

`<content></content>`

### JPG

The fuzzing of jpg includes various strategies:

- Empty file
- Large file
- Bit flips
- Known file header mutations
- Random file header mutations

In the case of random file header mutations, the first 4 bytes of the file are mutated with random integers converted back to bytes.

## Logging

A detailed log file is generated at `/tmp/aaaalog`. This file logs:

- input tried
- program stdout
- any logging information from the fuzzer.

## Testing

Test binaries written in C were used to test our fuzzer functionality and implementation. These include programs similar to the provided programs, in taking in similar data formats.

## Improvements

We did not do ELF nor PDF, thus adding support for these two formats would 
already be an improvement. Additionally, fuzzing for each format could have
been more in-depth, focusing a bit more on other vulnerabilities at a higher
level such as format strings and logic errors. 

Although we did not have time to properly implement something awesome, we had
an idea to create a front-end where users are able to drop binary files in, 
and our fuzzer would run, attempting to find vulnerabilities. Found vulnerabilites
would then be printed into a file, which would then be given to the user. 

We were able to implement a simple version of code coverage that explores all the 
possible paths. This allows us to ensure that most if not all vulnerabilities are 
discovered. However, the implementation was complicated and may be confusing. A welcome 
improvement would be to add multithreading. Through multithreading, we will be able 
to enhance the performance and efficiency of the fuzzer. With this, we would be able
to run more fuzzing techniques within the same amount of time. Additionally, 
multithreading will improve the implementation of code coverage by having a dedicated
thread that monitors and tracks the code coverage of binaries more accurately. 
