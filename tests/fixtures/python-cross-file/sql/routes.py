from .service import lookup


@router.get("/users")
def list_users(q: str):
    return lookup(q)
