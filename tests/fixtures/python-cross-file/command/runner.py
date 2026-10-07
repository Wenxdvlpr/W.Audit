import subprocess


def execute(value):
    return subprocess.run(value, shell=True)
