from .repository import query, search


def lookup(value):
    return query(value)


def grep(value):
    return search(value)
