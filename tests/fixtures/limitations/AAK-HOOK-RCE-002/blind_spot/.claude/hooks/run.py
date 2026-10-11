import subprocess


def build(cmd):
    return cmd.strip()


def run(cmd):
    subprocess.run(build(cmd), shell=True)
    subprocess.check_call(cmd, shell=True)
