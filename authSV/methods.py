import base64

from authSV.helpers import encode, decode, GetTOTP


def GenChallengeAnswer(challenge_hash: str, client_private_hash: str) -> str:
    data = {
        "challenge_hash": challenge_hash,
        "client_private_hash": client_private_hash,
    }
    # print(client_private_hash.encode("utf-8"))
    key = GetTOTP(b"SV")
    return encode(key=bytes(key, 'utf-8'), data=str(data).encode("utf-8"))


def Validate(challenge_answer: str, client_private_hash: str):
    key = GetTOTP(b"SV")
    r = None
    try:
        r = decode(enc=challenge_answer, key=bytes(key, 'utf-8'))
    except Exception:
        return ""
    if r:
        return base64.urlsafe_b64encode(bytes(r + client_private_hash, "utf-8"))
