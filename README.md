# SecureChat
Encrypted chat server and client written in Python

## About
This is a project intended to demonstrate the use of key exchange and encryption in a simple chat program. It establishes a shared encryption key with each connecting client through a [Diffie-Hellman key exchange](https://en.wikipedia.org/wiki/Diffie–Hellman_key_exchange), which the client and server then use to encrypt and decrypt each-other's messages via [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard).

## Disclaimer
This program does not make use of any further security standards such as host or message integrity verification (i.e. certification and inclusion of message or session IDs). As the program was built to be easy to understand and learn from, I would not trust it for private communication and instead read through the code to gain a basic understanding of the technologies that underlie modern encrypted communication.

## Setup

### Prerequisites
* Python 3
* pycrypto
* m2crypto

### Client
```
$ python client.py [host] [--port]
```

### Server
```
$ python server.py [--host] [--port]
```
