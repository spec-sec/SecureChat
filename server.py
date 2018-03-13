#!/usr/bin/env python
"""
SecureChat server: starts a server that routes chat messages.
"""

import socket
import threading
import sys
import binascii
import argparse
from M2Crypto import DH as M2DH
from dhke import DH, DH_SIZE, LEN_PK
from cipher import Message

__author__ = "spec"
__license__ = "MIT"
__version__ = "0.1"
__status__ = "Development"

# The number of unaccepted connections that the system will allow
# before refusing new connections.
BACKLOG = 5

# The default port the server should use.
DEFAULT_PORT = 39482


class Server:

    def __init__(self, host='127.0.0.1', port=DEFAULT_PORT):
        """
        Initialize a new server object.
        :param host: IP address of the server
        :param port: Port to use for the server
        """
        print("SecureChat Sever v{}".format(__version__))
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Generate Diffie-Hellman Key Exchange Parameters
        print("Generating a {}-bit prime...".format(DH_SIZE))
        self.dh_params = M2DH.gen_params(DH_SIZE, 2)
        print("Done!")
        self.clients = []
        # Start the server, break on ^C
        try:
            self.start()
        except KeyboardInterrupt:
            print("\rExiting...")
            [self.disconnect(client) for client in self.clients]
            self.socket.close()
            sys.exit()

    def start(self):
        """
        Wait for clients to connect, perform DHKE with each new
        connection, then listen for incoming messages.
        """
        # Bind server socket
        self.socket.bind((self.host, self.port))
        print("Socket bound to {} on port {}".format(self.host, self.port))
        # Start listening on the socket
        self.socket.listen(BACKLOG)
        print("Waiting for Clients...")
        while True:
            # Create a new socket for an incoming client
            connection, address = self.socket.accept()
            print("{} has connected".format(address[0]))
            # Create new client object for this connection
            client = Client(self, connection, address)
            # Wait for next client if key exchange failed
            if not client.key:
                client.connection.close()
                print("{} has disconnected".format(client.address[0]))
                continue
            print("Client Key: {}".format(binascii.hexlify(client.key).decode("utf-8")))
            # Add client to list of clients on server
            self.clients.append(client)
            self.broadcast("{} has joined".format(client.address[0]), client, show_address=False)
            # Listen for incoming messages from client
            threading.Thread(target=self.listen, args=(client, )).start()

    def listen(self, client):
        """
        Receive and handle data from a client.
        :param client: client to receive data from
        """
        while True:
            try:
                # Wait for data from client
                data = client.connection.recv(1024)
                # Disconnect client if no data received
                if not data:
                    self.disconnect(client)
                    break
                print("{} [Raw]: {}".format(client.address[0], data))
                # Parse data as cipher-text message
                msg = Message(key=client.key, ciphertext=data)
                print("{} [Decrypted]: {}".format(client.address[0], msg.plaintext))
                if msg.plaintext == "!exit":
                    client.send("Acknowledged")
                    self.disconnect(client)
                    continue
                self.broadcast(msg.plaintext, client)
            # Disconnect client if unable to read from connection
            except OSError:
                self.disconnect(client)
                break

    def broadcast(self, content, from_client, show_address=True):
        if show_address:
            msg = from_client.address[0] + ": " + content
        else:
            msg = content
        [client.send(msg) for client in self.clients if client is not from_client]

    def disconnect(self, client):
        """
        Disconnect a client from the server.
        :param client: client to be disconnected
        """
        client.connection.close()
        if client in self.clients:
            disconnect_msg = "{} has disconnected".format(client.address[0])
            self.broadcast(disconnect_msg, client, show_address=False)
            try:
                self.clients.remove(client)
            except ValueError:
                pass
            print(disconnect_msg)


class Client:

    def __init__(self, server, connection, address, user=None):
        """
        Initialize a new client on a server.
        :param server: the server to which the client belongs
        :param connection: the socket on which the server communicates with the client
        :param address: the IP address and port of the client
        :param user: the User object the client is logged in as (not yet implemented)
        """
        self.connection = connection
        self.address = address
        self.user = user
        self.key = self.dh(server.dh_params)

    def dh(self, dh_params):
        """
        Perform Diffie-Hellman Key Exchange with a client.
        :param dh_params: p and g generated by DH
        :return shared_key: shared encryption key for AES
        """
        # p: shared prime
        p = DH.b2i(dh_params.p)
        # g: primitive root modulo
        g = DH.b2i(dh_params.g)
        # a: randomized private key
        a = DH.gen_private_key()
        # Generate public key from p, g, and a
        public_key = DH.gen_public_key(g, a, p)
        # Create a DH message to send to client as bytes
        dh_message = bytes(DH(p, g, public_key))
        self.connection.sendall(dh_message)
        # Receive public key from client as bytes
        try:
            response = self.connection.recv(LEN_PK)
        except ConnectionError:
            print("Key Exchange with {} failed".format(self.address[0]))
            return None
        client_key = DH.b2i(response)
        # Calculate shared key with newly received client key
        shared_key = DH.get_shared_key(client_key, a, p)
        return shared_key

    def send(self, content):
        """
        Encrypt and send a message to the client
        :param content: plaintext content to be encrypted
        """
        msg = Message(key=self.key, plaintext=content)
        self.connection.sendall(msg.pack())

    def decrypt(self, content):
        """
        Decrypt an encrypted message.
        :param content: encrypted message content to be decrypted
        :return: decrypted message
        """
        return Message(key=self.key, ciphertext=content).plaintext


if __name__ == '__main__':
    # Get host and port arguments from the command-line
    aparser = argparse.ArgumentParser()
    aparser.add_argument("--host", default='127.0.0.1', help="IP address of the chat server")
    aparser.add_argument("--port", default=DEFAULT_PORT, type=int, help="Port number the chat server is running on")
    args = aparser.parse_args()
    s = Server(host=args.host, port=args.port)

