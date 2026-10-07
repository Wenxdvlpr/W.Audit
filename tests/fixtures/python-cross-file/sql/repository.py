def query(value):
    statement = value
    return db.execute("SELECT * FROM users WHERE name = '" + statement + "'")
