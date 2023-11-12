import subprocess

def check_type(sample_binary_str):
    cmd = ['file', sample_binary_str]
    ret = subprocess.run(cmd, stdout=subprocess.PIPE, text=True)

    if 'CSV ASCII text' in ret.stdout:
        return 'csv'
    elif 'JSON text data' in ret.stdout:
        return 'json'
    elif 'HTML document, ASCII text' in ret.stdout:
        return 'xml'
    elif 'ASCII text' in ret.stdout:
        return 'plaintext'