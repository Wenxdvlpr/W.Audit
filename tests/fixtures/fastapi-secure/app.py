from fastapi import Depends


@app.get("/admin/users/{user_id}")
def get_admin_user(user_id: str, current_user=Depends(get_current_user), role=Depends(require_role("admin"))):
    return db.get(user_id)
