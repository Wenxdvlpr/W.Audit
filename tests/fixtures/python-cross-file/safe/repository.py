import subprocess


def query(value):
    return db.execute("SELECT * FROM users WHERE name = ?", (value,))


def search(value):
    return subprocess.run(["grep", value], shell=False)
