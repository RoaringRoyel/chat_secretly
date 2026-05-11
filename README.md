# CSE721 Cryptography Project: FastAPI Crypto Lab + Encrypted Chat

Educational FastAPI project implementing classical and modern cryptographic algorithms from scratch for demonstration and analysis.
# Live link : https://chat-secretly.onrender.com/

## Features

- User registration and login
- Friend/user search by username with substitution-cipher demo
- Simple encrypted chat between registered users
- Message encryption/decryption demo panel
- Crypto Lab tab for:
  - Substitution cipher with brute force helper and frequency analysis
  - Double transposition cipher with frequency analysis
  - DES educational block implementation with round keys
  - AES-128 implementation with round keys
  - RSA key generation, encryption, decryption, and trial-division factorization demo
  - ECC point listing and ECDH shared key demo

## Important academic note

This project is for coursework and demonstration. The included algorithms are written from scratch for learning. Do not use this code to protect real systems. Real applications should use vetted cryptographic libraries and protocols.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open: http://127.0.0.1:8000

## Default assumptions

- AES uses 128-bit keys and PKCS#7 padding.
- DES uses an 8-byte key and PKCS#7 padding.
- Chat messages use the custom AES implementation with a server-side demo key.
- Passwords are stored with an educational custom SHA-like hash plus salt. This is to satisfy demonstration requirements only.
- Data is stored in SQLite.
- RSA factorization attack uses trial division and is only practical for small keys.

## Project structure

```text
app/
  main.py              FastAPI routes
  db.py                SQLite helpers
  auth.py              login/session helpers
  crypto/
    substitution.py
    double_transposition.py
    aes.py
    des.py
    rsa.py
    ecc.py
    hash_demo.py
  templates/
    base.html
    index.html
    login.html
    register.html
    chat.html
    lab.html
  static/
    style.css
```
