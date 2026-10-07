import os
import subprocess
import pickle

def run(user_input):
    os.system(user_input)
    subprocess.run(user_input, shell=True)
    return pickle.loads(user_input)
