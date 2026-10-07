from fastapi import FastAPI

app = FastAPI()


def repository(value):
    db.execute(f"SELECT * FROM users WHERE name = '{value}'")


def service(value):
    alias = value
    return repository(alias)


@app.get("/users")
def endpoint(q):
    return service(q)
