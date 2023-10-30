#created by: hfg0016


import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3

connection = sqlite3.connect("totally_not_my_privateKeys.db")

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

plaintext = private_key.decrypt(
        cyphertext,
        padding.OAEP()
)

cursor = connection.cursor()

cursor.execute("""CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)""");

connection.commit()

connection.close()

print(plaintext)
