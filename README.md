# aaaafuzzer
fuzzer for 32 bit binaries 

## Overall design

- main fuzzer code in `fuzzer.py`
- main payload generation and fuzzer functions in `payloads.py`
    - `bad.txt` will be created only if a crash is detected
- helpers in `checkType.py` and `util.py`
- log files can be found at `/tmp/aaaalog`

## How it works 

The fuzzer works by sending in various mutated inputs in hopes that an 
unsupported input will cause a segmentation fault. To obtain these
mutated inputs, the team has developed various mutation strategies to
greatly increase the chance of finding a segmentation fault. 
1. Repeating sample input: Multiplying the content to the power of n.
2. Bit flips: This has two different kind of implementations. One is 
getting a string, flipping a specified bit and then returning the string.
The other is a walking bit flip implentation, where walks to a specifed
bit, flipping all the bits on its path. The string is then returned.
3. Random character flipping: Gets a string, flips a random character
and then returns the string.
4. Random strings: Generates random string within the specified parameters.
5. Integer json enlargement: Changes integer values with larger integer values.
6. String json enlargement: Takes a json string and greatly increases its length using cyclic.
7. Key json enlargement: Takes a json key and increases its size. 

One of the key aspects we target are buffer overflows, a key vulnerability that 
could lead to numerous exploits such as leakage of information. Nevertheless,
when a crash is detected, a file called `bad.txt` is generated. 

## Harness capabilities
The harness is able to detect crashes that occuer when an invalid input is given.
It also checks if there are infinite while loops by keeping track of the time. 
If the time goes over a certain threshold, it will exit the program. 


## Bugs our fuzzer finds
- Information leaks
- Buffer overflow
- Format string
- Integer overflow
- Logic errors

### For JSON:
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

### For XML:
The team tests XML for unexpected input such as empty file, fuzzing xml tags, 
child tags and xml content. Additionally, fuzzer is also run on xml atrributes and
also checks for format string vulnerabilities. Through changing the values of tags
and attributes, it will likely reveal any vulnerabilities by causing a segmentation
fault. 

An example sample input is the following:
`somethingidk`

### For JPEG:
The fuzzing of jpeg begins with the testing of an empty file and a large file and
observing if such cases are handled correctly. If they are not, there will be a 
segmentation fault, possible containing valuable information. 

An example sample input is the following:
`somethingidk`

### For Plaintext:
We have constructed a variety of inputs testing for crashes. One such test is for 
logic errors, checking if it supports empty and very large files. In addition, 
we test for support on various integers, testing to see if unexpected input may
contain a logic flaw. Bit flipping is also used on the whole file in various 
formats, in addition to random mutations to further test if there are any
vulnerabilities in all kinds of characters.

An example sample input is the following:
`somethingidk`

## Improvements
We did not do ELF nor PDF, thus adding support for these two formats would 
already be an improvement. Additionally, fuzzing for each format could have
been more in-depth, focusing a bit more on other vulnerabilities at a higher
level such as format strings and logic errors. 

We were unable to figure out code coverage, but if this were to be 
implemented it would greatly increase the efficiency of our fuzzing through
coverage based mutation, which would ensure that all paths are covered. 
Being able to throughly test the whole program through coverage will give
the greatest chance of finding security vulnerabilities and logic errors. 
It also speeds up the fuzzing process it will allow the fuzzer to focus more
on finding new paths rather then revisiting similar paths. 


## Something Awesome
Front-end stuff