import requests
import hashlib
import re

req = requests.session()
url = "http://docker.hackthebox.eu:31016"

rget = req.get(url)
html = str(rget.content)

input_text = html.split(">")[9].split("<")[0]

mdhash = hashlib.md5(input_text.encode('utf-8')).hexdigest()

### sending a Post request

data = dict(hash= mdhash)
rpost = req.post(url=url, data=data)

# getting rpost
print(rpost.text)


