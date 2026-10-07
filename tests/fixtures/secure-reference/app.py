import subprocess

def run(argument):
    return subprocess.run(["/usr/bin/true", argument], shell=False, check=True)
