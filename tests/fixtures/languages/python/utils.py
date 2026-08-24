import re


def validate_email(email):
    return bool(re.match(r"[^@]+@[^@]+\.[^@]+", email))


def format_response(data):
    if isinstance(data, list):
        return {"items": data, "count": len(data)}
    return {"item": data}


def deprecated_helper():
    pass
