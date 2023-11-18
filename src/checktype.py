import subprocess

def check_type(sample_binary_str):
    cmd = ['file', sample_binary_str]
    ret = subprocess.run(cmd, stdout=subprocess.PIPE, text=True)

    if 'CSV' in ret.stdout:
        return 'csv'
    elif 'JSON' in ret.stdout:
        return 'json'
    elif 'HTML document' in ret.stdout:
        return 'xml'
    elif 'JPEG' in ret.stdout:
        return 'jpeg'
    elif 'ASCII text' in ret.stdout:
        return 'plaintext'