import hashlib

md5_hash = hashlib.md5(b'o4Qx2XZWR9uRXetOIQNl')

print(dir(md5_hash))
print(md5_hash.digest())