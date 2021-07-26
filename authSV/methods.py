from authSV.helpers import encode, decode, GetTOTP


def GenChallenge(challenge_hash, client_private_hash):
    data = {
        "challenge_hash": challenge_hash,
        "client_private_hash": client_private_hash,
    }

    key = GetTOTP(b"SV")
    return encode(key=bytes(key, 'utf-8'), data=str(data).encode("utf-8"))
