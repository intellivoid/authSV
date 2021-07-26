import base64
import hashlib
import hmac
import re
import struct
import time
from itertools import cycle


# https://stackoverflow.com/a/9807138/14897316


def GetTokenInterval(secret, intervals_no):
    key = decode_base64(secret)
    msg = struct.pack(">Q", intervals_no)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    stuc = stuc = h[19] & 15
    h = (struct.unpack(">I", h[stuc:stuc + 4])[0] & 0x7fffffff) % 1000000
    return h


def GetTOTP(secret) -> str:
    x = str(GetTokenInterval(secret, intervals_no=int(time.time()) // 30))
    while len(x) != 6:
        x += '0'
    h = hashlib.blake2b(key=int(x).to_bytes(5, 'little'), digest_size=16)
    return h.hexdigest()


# --------------------------------------------------------------------------------------------------------

def decode_base64(data, altchars=b'+/'):
    """Decode base64, padding being optional.

    :param altchars: [Optional: Default is b'+/'] padding
    :param data: Base64 data as an ASCII byte string
    :returns: The decoded byte string.

    """
    data = re.sub(rb'[^a-zA-Z0-9%s]+' % altchars, b'', data)  # normalize
    missing_padding = len(data) % 4
    if missing_padding:
        data += b'=' * (4 - missing_padding)
    return base64.b64decode(data, altchars)


# --------------------------------------------------------------------------------------------------------


def encode(data, key):
    return base64.urlsafe_b64encode(key + data)


def decode(enc, key):
    return base64.urlsafe_b64decode(enc)[len(key):].decode('utf-8')
