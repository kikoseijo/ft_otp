import hashlib
import hmac
import math
from datetime import datetime


class OTP(object):
    def __init__(self, secret: str):
        self.secret = secret

    def generate(self) -> str:
        presentDate = datetime.now()
        unix_timestamp = datetime.timestamp(presentDate)
        current_time = int(unix_timestamp // 30)
        current_time = math.floor(current_time)
        current_time = str(current_time)
        print(current_time)
        hash_bytes = hmac.digest(self.secret.encode('utf-8'), current_time.encode('utf-8'),hashlib.sha1)
        offset = hash_bytes[19] & 0xf
        password = 0
        password |= hash_bytes[offset] << 24
        password |= hash_bytes[offset + 1] << 16
        password |= hash_bytes[offset + 2] << 8
        password |= hash_bytes[offset + 3]
        password = password % 1000000
        print(password)
        min_len = lambda x: "{:06d}".format(x)
        return min_len(password)
