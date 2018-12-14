import json
import hashlib
from sys import version_info

from datetime import datetime

IS_PY3 = version_info[0] >= 3

if IS_PY3:
    import email.utils as rfc822
else:
    import rfc822


def rfc822_timestamp(time_string):
    return datetime.fromtimestamp(rfc822.mktime_tz(rfc822.parsedate_tz(time_string)))


def uri_to_bucket_and_object(uri):
    if not uri.startswith("fds://"):
        return None, None

    bucket_object_pair = uri[6:].split('/', 1)
    bucket = bucket_object_pair[0]
    object = bucket_object_pair[1]
    return bucket, object


def to_json_object(src):
    if isinstance(src, bytes):
        src = src.decode(encoding='utf-8')
    if src:
        return json.loads(src)
    return None

def file_md5(filename, blocksize=2**20):
    m = hashlib.md5()
    with open(filename, "rb") as f:
        while True:
            buf = f.read(blocksize)
            if not buf:
                break
            m.update(buf)
    return m.hexdigest()
