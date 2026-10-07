from .client import request_url


def fetch(value):
    alias = value
    return request_url(alias)
