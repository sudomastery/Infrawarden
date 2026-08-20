import base64


def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64decode(data: str) -> bytes:
    # validate=True rejects non-alphabet characters instead of silently
    # discarding them (which would otherwise store corrupted ciphertext with no
    # way to detect it later, in append-only rows that are never rewritten).
    # Malformed input (bad padding, invalid characters) raises binascii.Error,
    # translated to a clean 400 by the handler registered in app.main.
    return base64.b64decode(data, validate=True)
