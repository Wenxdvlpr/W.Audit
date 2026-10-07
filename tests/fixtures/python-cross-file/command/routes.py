from .service import invoke


@router.post("/run")
def run_task(command: str):
    return invoke(command)
