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
- helpers in `check_type.py` and `util.py`
- log files can be found at `/tmp/aaaalog.log`