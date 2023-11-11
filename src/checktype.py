import subprocess

def check_type(sample_binary_str):
    cmd = ['file', sample_binary_str]
    ret = subprocess.run(cmd, stdout=subprocess.PIPE, text=True)

    if 'ASCII text' in ret.stdout:
        return 'plaintext'
    if 'CSV ASCII text' in ret.stdout:
        return 'csv'
    if 'JSON text data' in ret.stdout:
        return 'json'
    if 'HTML document, ASCII text' in ret.stdout:
        return 'xml'
