# EXPECTED: NOT SCANNED — vendor/ is default-ignored (gh #46). This MD5 must not appear.
import hashlib
def h(x): return hashlib.md5(x).hexdigest()
