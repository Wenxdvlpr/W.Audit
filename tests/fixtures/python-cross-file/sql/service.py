from .repository import query


def lookup(value):
    alias = value
    return query(alias)
