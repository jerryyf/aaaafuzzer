# aaaafuzzer
fuzzer for 32 bit binaries

## Functionality

- stdin fuzzing
    - buffer overflow detection
    - format string vulnerability detection
- file input fuzzing
    - file mutation based on a given file
        - csv and json (so far)
        - generates `bad.txt` which may or may not find vulnerabilities (so far)

## Overall design

- main fuzzer code in `fuzzer.py`
- main payload generation and fuzzer functions in `payloads.py`
- helpers in `check_type.py` and `util.py`