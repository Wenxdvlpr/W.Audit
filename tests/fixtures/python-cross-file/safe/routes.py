from .service import lookup, grep


@router.get("/users")
def list_users(q: str):
    return lookup(q)


@router.get("/grep")
def search(term: str):
    return grep(term)
