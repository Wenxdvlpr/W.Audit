from .service import fetch


@router.get("/preview")
def preview(url: str):
    return fetch(url)
