#!/usr/bin/env python
"""
SecureChat client: communicates with server and initializes user interface.
"""

import socket
import threading
import sys
import binascii
import argparse
from server import DEFAULT_PORT
from dhke import DH, DH_MSG_SIZE, LEN_PK
from cipher import Message
from cli import CLI

__author__ = "spec"
__license__ = "MIT"
__version__ = "0.1"
__status__ = "Development"


class Client:

    def __init__(self, interface, server_address, port=DEFAULT_PORT):
        """
        Initialize a new client.
        :param server_address: IP address of the server
        :param port: Server port to connect to
        """
        self.cli = interface
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.cli.add_msg("Connecting to {}...".format(server_address))
        try:
            self.connection.connect((server_address, port))
        except KeyboardInterrupt:
            self.cli.clean_exit()
            sys.exit()
        self.cli.add_msg("Connected!")
        self.key = None

    def dh(self):
        """
        Perform Diffie-Hellman Key Exchange with the server.

        p: prime modulus declared by the server
        g: generator declared by the server
        server_key: the server's public key

        private_key: the client's private key
        public_key: the client's public key

        :return shared_key: the 256-bit key both the client and
        server now share
        """
        self.cli.add_msg("Establishing Encryption Key...")
        dh_message = self.connection.recv(DH_MSG_SIZE)
        # Unpack p, g, and server_key from the server's dh message
        p, g, server_key = DH.unpack(dh_message)
        # Generate a randomized private key
        private_key = DH.gen_private_key()
        # Send the server a public key which used the previously
        # Generated private key and both g and p
        public_key = DH.gen_public_key(g, private_key, p)
        self.connection.sendall(DH.package(public_key, LEN_PK))
        # Calculate shared key
        shared_key = DH.get_shared_key(server_key, private_key, p)
        # print("Shared Key: {}".format(shared_key))
        self.cli.add_msg("Encryption Key: {}".format(binascii.hexlify(shared_key).decode("utf-8")))
        return shared_key

    def send(self, content):
        """
        Send a message to the server.
        :param content: string to encrypt and send
        """
        if not self.key:
            self.cli.add_msg("Error: Key Not Established")
            return
        msg = Message(key=self.key, plaintext=content)
        self.connection.sendall(msg.pack())

    def start(self):
        """
        Start the client: perform key exchange and start listening
        for incoming messages.
        """
        try:
            self.key = self.dh()
        except ConnectionError:
            self.cli.add_msg("Unable to Connect")
            return
        while True:
            try:
                # Wait for data from server
                data = self.connection.recv(1024)
                # Disconnect from server if no data received
                if not data:
                    self.connection.close()
                    self.cli.uninit_client()
                    break
                # Parse data as cipher-text message
                msg = Message(key=self.key, ciphertext=data)
                if not self.cli:
                    break
                # Add message to the command-line interface
                self.cli.add_msg(msg.plaintext)
            # Disconnect client if unable to read from connection
            except OSError:
                self.connection.close()
                self.cli.uninit_client()
                break


if __name__ == '__main__':
    # Get host and port arguments from the command-line
    aparser = argparse.ArgumentParser()
    aparser.add_argument("host", help="IP address of the chat server")
    aparser.add_argument("--port", default=DEFAULT_PORT, type=int, help="Port number the chat server is running on")
    args = aparser.parse_args()
    # Initialize Command-Line Interface
    interface = CLI()
    try:
        c = Client(interface, args.host, port=args.port)
    except ConnectionRefusedError:
        interface.clean_exit()
        print("Connection Refused")
        sys.exit()
    except OSError:
        interface.clean_exit()
        print("Connection Failed")
        sys.exit()
    # Add the client object to the interface
    interface.init_client(c)
    # Start the client
    client_thread = threading.Thread(target=c.start)
    client_thread.start()
    # Start the main input loop
    try:
        interface.main()
    except KeyboardInterrupt:
        interface.clean_exit()
