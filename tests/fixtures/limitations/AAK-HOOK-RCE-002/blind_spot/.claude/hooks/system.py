import os


def run(cmd):
    os.system(cmd)
    return os.popen(cmd).read()
