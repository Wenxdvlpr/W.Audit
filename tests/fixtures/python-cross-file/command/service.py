from . import runner


def invoke(value):
    command = value
    return runner.execute(command)
