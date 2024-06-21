"""
Description:
This Python file contains utility functions used by Client
and Server classes.

"""
import gc
import ipaddress
import os
import pickle
import secrets
import socket
import time
from typing import TextIO
from prettytable import PrettyTable
from tinyec.ec import Inf
from models.CustomCipher import CustomCipher
from utility.cipher_utils import write_to_file
from utility.constants import (MENU_TITLE, MENU_FIELD_OPTION, MENU_FIELD_DESC, CLIENT_MENU_OPTIONS_LIST,
                               SERVER_MENU_OPTIONS_LIST, INVALID_MENU_SELECTION,
                               MENU_ACTION_START_MSG, INVALID_INPUT_MENU_ERROR, MIN_PORT_VALUE,
                               MAX_PORT_VALUE, CONNECTION_INFO_FIELD_NAME, CONNECTION_INFO_FIELD_IP,
                               CONNECTION_INFO_FIELD_SECRET, CONNECTION_INFO_FIELD_IV, CONNECTION_INFO_TITLE, CBC,
                               BLOCK_SIZE, CONNECTION_INFO_FIELD_CIPHER_MODE, MODE_SERVER, MODE_CLIENT,
                               CLIENT_MENU_CONNECTED_OPTIONS_LIST, TRANSFER_FILE_PATH_PROMPT, FORMAT_FILE,
                               FILE_TRANSFER_SIGNAL, FORMAT_BYTES, ACK, SAVE_FILE_DIR, END_OF_FILE,
                               FILE_TRANSFER_BULK_SIGNAL)
from utility.ec_keys_utils import derive_shared_secret, compress


def encrypt(cipher: CustomCipher, plain_text: str | bytes, format=None, verbose=True):
    """
    An abstraction function that invokes the CustomCipher
    to encrypt plaintext with a 16-byte (128-bit) shared
    secret key derived from ECDH.

    @param cipher:
        A CustomCipher object

    @param plain_text:
        A string representing the plaintext to
        be encrypted

    @param format:
        A string denoting the format of the encryption
        (FILE, TEXT, STRING, etc.)

    @param verbose:
        A boolean indicating to turn on verbose mode
        (default=True)

    @return: cipher_text
        The encrypted ciphertext (string)
    """
    if format == FORMAT_FILE:
        ciphertext = cipher.encrypt(plain_text, format=FORMAT_FILE, verbose=verbose)
    else:
        ciphertext = cipher.encrypt(plain_text, verbose=verbose)
    return ciphertext


def decrypt(cipher: CustomCipher, cipher_text: bytes, format=None, verbose=True):
    """
    An abstraction function that invokes the CustomCipher
    to decrypt ciphertext with a 16-byte (128-bit) shared
    secret key derived from ECDH.

    @param cipher:
        A CustomCipher object

    @param cipher_text:
        An array of bytes containing encrypted data

    @param format:
        An optional parameter to indicate the type of format
        to return (Bytes or Decoded String)

    @param verbose:
        A boolean indicating to turn on verbose mode
        (default=True)

    @return: plain_text
        The decrypted plaintext (string)
    """
    if format == FORMAT_BYTES:
        plain_text = cipher.decrypt(cipher_text, format=FORMAT_FILE, verbose=verbose)  # Return bytes
    else:
        plain_text = cipher.decrypt(cipher_text, verbose=verbose)  # Return decoded string
    return plain_text


def display_menu(is_connected: bool = False, is_server: bool = False):
    """
    Displays the menu for user commands.

    @param is_connected:
        A boolean determining whether a client is connected

    @param is_server:
        A boolean representing whether calling class is Server
        (display server menu options)

    @return: None
    """
    menu = PrettyTable()
    menu.title = MENU_TITLE
    menu.field_names = [MENU_FIELD_OPTION, MENU_FIELD_DESC]

    if is_server:
        for item in SERVER_MENU_OPTIONS_LIST:
            menu.add_row(item)
    elif is_connected:
        for item in CLIENT_MENU_CONNECTED_OPTIONS_LIST:
            menu.add_row(item)
    else:
        for item in CLIENT_MENU_OPTIONS_LIST:
            menu.add_row(item)

    print(menu)


def view_current_connections(self: object, is_server: bool = False):
    """
    Displays information of all current connections.

    @param self:
        A reference to the calling class object

    @param is_server:
        A boolean to determine if calling class is a
        server (default = False)

    @return: None
    """
    # Instantiate table and define title & columns
    table = PrettyTable()
    table.title = CONNECTION_INFO_TITLE
    table.field_names = [CONNECTION_INFO_FIELD_NAME, CONNECTION_INFO_FIELD_IP,
                         CONNECTION_INFO_FIELD_CIPHER_MODE, CONNECTION_INFO_FIELD_SECRET,
                         CONNECTION_INFO_FIELD_IV]

    # Fill table with data
    if is_server:
        if len(self.fd_list) > 1:
            for ip, information in self.client_dict.items():  # Format: (Name, IP, Mode, Shared Secret, IV)
                table.add_row([information[0], ip, information[3].upper(), information[1],
                               information[2].hex() if information[2] else None])
            print(table)
        else:
            print("[+] VIEW CURRENT CONNECTIONS: There are no current connections to view!")
    else:
        if len(self.fd_list) > 0:
            table.add_row([self.server_name, self.server_socket.getpeername()[0],
                           self.cipher.mode.upper(), self.shared_secret,
                           self.cipher.iv.hex() if self.cipher.iv else None])
            print(table)
        else:
            print("[+] VIEW CURRENT CONNECTIONS: There are no current connections to view!")


def close_application(self: object):
    """
    Terminates the application by setting a termination flag to
    end all current threads.

    @param self:
        A reference to the calling class object

    @return: None
    """
    print("[+] CLOSE APPLICATION: Now closing the application...")
    self.terminate = True  # Set a terminate flag to terminate all threads
    print("[+] Application has been successfully terminated!")


def get_user_menu_option(fd: TextIO, min_num_options: int, max_num_options: int):
    """
    Gets the user selection for the menu.

    @param fd:
        The file descriptor for standard input

    @param min_num_options:
        The minimum number of options possible

    @param max_num_options:
        The maximum number of options possible

    @return: command
        An integer representing the selection
    """
    command = fd.readline().strip()

    try:
        command = int(command)
        while not (min_num_options <= command <= max_num_options):
            print(INVALID_MENU_SELECTION.format(min_num_options, max_num_options))
            command = fd.readline().strip()
        print(MENU_ACTION_START_MSG.format(command))
        return command
    except (ValueError, TypeError) as e:
        print(INVALID_INPUT_MENU_ERROR.format(e))
        print(INVALID_MENU_SELECTION.format(min_num_options, max_num_options))


def __get_target_ip():
    """
    A helper function that gets the target IP address
    from user prompt.

    @raise ValueError
        Exception raised if the target IP address is invalid

    @return: ip_address
        A string representing the target IP address
    """
    while True:
        try:
            ip_input = input("[+] Enter the IP address of the target server: ")
            ip_address = str(ipaddress.ip_address(ip_input))
            return ip_address
        except ValueError:
            print("[+] Invalid IP address; please enter again.\n")


def __get_target_port():
    """
    A helper function that gets the target port
    from user prompt.

    @raise ValueError:
        Exception raised if the target port is of invalid format

    @raise TypeError:
        Exception raised if the user inputs not an integer value

    @return: port
        An integer representing the target port
    """
    while True:
        try:
            port = int(input("\n[+] Enter the port number of the target server: "))
            while port not in range(MIN_PORT_VALUE, MAX_PORT_VALUE):
                print("[+] ERROR: Invalid port number range; please enter again.")
                port = int(input("\n[+] Enter the port number of the target server: "))
            return port
        except ValueError as e:
            print(f"[+] ERROR: An invalid port number was provided ({e}); please enter again.")
        except TypeError as e:
            print(f"[+] ERROR: An invalid port number was provided ({e}); please enter again.")


def exchange_public_keys(pub_key: Inf, sock: socket.socket, mode: str):
    """
    Performs the ECDH public key exchange process.

    @param pub_key:
        The public key to send over

    @param sock:
        A socket object

    @param mode:
        A string to denote whether calling class is
        a server or client

    @return: Public Key
        The other end's public key
    """
    if mode == MODE_SERVER:
        print("[+] KEY EXCHANGE: Now exchanging keys with new client...")

        # Receive Client's Public Key
        serialized_client_pub_key = sock.recv(4096)
        client_pub_key = pickle.loads(serialized_client_pub_key)

        # Send over the public key to the client
        serialized_key = pickle.dumps(pub_key)
        sock.sendall(serialized_key)
        return client_pub_key

    if mode == MODE_CLIENT:
        print("[+] KEY EXCHANGE: Now exchanging keys with the server...")

        # Send Public Key to Server
        serialized_key = pickle.dumps(pub_key)
        sock.sendall(serialized_key)

        # Receive Public Key from Server
        serialized_server_pub_key = sock.recv(4096)
        server_pub_key = pickle.loads(serialized_server_pub_key)
        return server_pub_key


def connect_to_server(self: object):
    """
    Prompts the user for the target IP address and port, and
    connects to the target using sockets.

    @attention Use Case:
        Client class only

    @raise socket.error
        Exception raised if the target host is offline or
        incorrect host information

    @param self:
        The calling object

    @return: None
    """
    target_ip = __get_target_ip()
    target_port = __get_target_port()
    iv = None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target_ip, target_port))
        print(f"[+] CONNECTION EVENT: Established a connection to server ({target_ip}, {target_port})")

        # Bind class attributes
        self.is_connected = True
        self.server_socket = sock

        # Send cipher suite (mode) to the server
        time.sleep(0.5)
        sock.send(self.cipher_mode.encode())
        print(f"[+] MODE SELECTED: The encryption mode chosen for this session is {self.cipher_mode.upper()}")

        # Generate new session IV and send to server (if CBC)
        if self.cipher_mode == CBC:
            iv = secrets.token_bytes(BLOCK_SIZE)
            time.sleep(0.5)
            sock.send(iv)
            print(f"[+] IV GENERATED: An initialization vector (IV) has been generated for this session ({iv.hex()})")

        # Exchange Public Keys with Server
        server_pub_key = exchange_public_keys(self.pub_key, sock, mode=MODE_CLIENT)
        print(f"[+] PUBLIC KEY RECEIVED: Successfully received the server's public key ({compress(server_pub_key)})")

        # Derive the shared secret (print in hex)
        shared_secret = derive_shared_secret(self.pvt_key, server_pub_key)  # In bytes
        self.shared_secret = shared_secret.hex()
        print(f"[+] KEY EXCHANGE SUCCESS: A shared secret has been derived for the current "
              f"session ({self.shared_secret}) | Number of Bytes = {len(shared_secret)}")

        # Instantiate CustomCipher Object (if CBC, save IV in it)
        if self.cipher_mode == CBC:
            self.cipher = CustomCipher(key=shared_secret, mode=self.cipher_mode, iv=iv)
        else:
            self.cipher = CustomCipher(key=shared_secret, mode=self.cipher_mode)

        # Receive name of server
        self.server_name = decrypt(self.cipher, cipher_text=sock.recv(1024))
        print(f"[+] RECEIVED SERVER NAME: The server's host name is {self.server_name}")

        # Send name to server
        sock.send(encrypt(self.cipher, self.name))
        print("[+] CLIENT NAME SENT: Your host name has been successfully sent to server.")

        # Add socket to fd_list (for select() monitoring)
        self.fd_list.append(sock)
        print(f"[+] CONNECTION SUCCESS: A secure session with {self.server_name} has been established!")
    except socket.error as e:
        print(f"[+] CONNECTION FAILED: Failed to connect to target server ({e}); please try again.")


def accept_new_connection_handler(self: object, own_sock: socket.socket):
    """
    A handler to accept a new client connection, which
    involves the ECDH public key exchange process and generation
    of shared secret with the client.

    @attention Use Case:
        Server class only

    @param self:
        A reference to the calling class object (Server)

    @param own_sock:
        The socket object of the calling class (Server)

    @return: None
    """
    client_iv = None
    client_socket, client_address = own_sock.accept()
    print(f"[+] NEW CONNECTION: Accepted a client connection from ({client_address[0]}, {client_address[1]})!")

    # Receive cipher mode from client
    mode = client_socket.recv(1024).decode()
    print(f"[+] MODE RECEIVED: The encryption mode selected by the client for this session is {mode.upper()}")

    # Receive IV from server (if CBC)
    if mode == CBC:
        client_iv = client_socket.recv(1024)
        print(f"[+] IV RECEIVED: The initialization vector (IV) has been received from the client ({client_iv.hex()})")

    # Exchange public keys with the client
    client_pub_key = exchange_public_keys(self.pub_key, client_socket, mode=MODE_SERVER)
    print(f"[+] PUBLIC KEY RECEIVED: Successfully received the client's public key ({compress(client_pub_key)})")

    # Derive the shared secret
    shared_secret = derive_shared_secret(self.pvt_key, client_pub_key)  # In bytes
    compressed_shared_secret = shared_secret.hex()
    print(f"[+] KEY EXCHANGE SUCCESS: A shared secret has been derived for the current "
          f"session ({compressed_shared_secret}) | Number of Bytes = {len(shared_secret)}")

    # Instantiate CustomCipher Object (if CBC, save IV in it)
    if mode == CBC:
        cipher = CustomCipher(key=shared_secret, mode=mode, iv=client_iv)
    else:
        cipher = CustomCipher(key=shared_secret, mode=mode)

    # Send information to the client using CustomCipher (in bytes)
    client_socket.send(encrypt(cipher, self.name))
    print("[+] SERVER NAME SENT: Your host name has been successfully sent to the client.")

    # Receive name from the client (encrypted)
    name = decrypt(cipher, cipher_text=client_socket.recv(1024))
    print(f"[+] RECEIVED CLIENT NAME: The client's host name is {name}")

    # Update client dictionary with the new client (include CustomCipher)
    self.fd_list.append(client_socket)
    self.client_dict[client_address[0]] = [name, compressed_shared_secret, client_iv, mode, cipher]
    print(f"[+] CONNECTION SUCCESS: A secure session with {name} has been established!")


def send_message(sock: socket.socket, cipher: CustomCipher):
    """
    Prompts user for a plaintext message, encrypts it
    and sends it to a target socket.

    @param sock:
        The target socket

    @param cipher:
        A CustomCipher object

    @return: None
    """
    if sock is not None:
        ip = sock.getpeername()[0]
        message = input(f"[+] Enter a message to send to ({ip}): ")
        cipher_text = encrypt(cipher, message)
        sock.send(cipher_text)
        print("[+] Your message has been successfully sent!")


def host_disconnect_handler(self: object, sock: socket.socket,
                            name: str, ip: str, is_server: bool):
    """
    A host disconnect handler that removes any previously
    connected host's state and resets parameters to default.

    @param self:
        A reference to the calling class object (Server or Client)

    @param sock:
        The socket object of the disconnected host

    @param name:
        A string for the name of the disconnected host

    @param ip:
        A string for the IP address of the disconnected host

    @param is_server:
        A boolean to determine if calling class is Server or Client

    @return: None
    """
    if is_server:
        del self.client_dict[ip]
    else:
        del self.cipher
        self.is_connected = False
        self.server_socket, self.server_name, self.shared_secret, self.cipher = (None, None, None, None)

    # Perform cleanup
    print(f"[+] Connection closed by ({name}, {ip})")
    self.fd_list.remove(sock)
    sock.close()
    gc.collect()  # => Garbage collection for saved CustomCipher objects


def receive_data(self: object, sock: socket.socket, is_server: bool = False):
    """
    Handles the receiving of data (or disconnections) from a socket.

    @attention Client Info Format (for reference)
        {IP: [name, shared_secret, IV, mode, cipher]}

    @param self:
        A reference to the calling class object (Server or Client)

    @param sock:
        A socket object summoned by select() with
        incoming data

    @param is_server:
        A boolean to determine if calling class is a
        server (default = False)

    @return: None
    """
    # Get address and data from the corresponding socket
    ip_address, _ = sock.getpeername()
    data = sock.recv(1024)

    # Handler for Server
    if is_server:
        client_info = self.client_dict[ip_address]  # => Get client info (and the corresponding cipher)
        if data:
            print(f"[+] Received data from [{client_info[0]}, {ip_address}] (encrypted): {data}")
            plain_text = decrypt(cipher=client_info[-1], cipher_text=data)
            print(f"[+] Received data from [{client_info[0]}, {ip_address}] (decrypted): {plain_text}")

            # File Transfer Handler
            if plain_text == FILE_TRANSFER_SIGNAL:
                receive_file(name=client_info[0], ip=ip_address, sock=sock, cipher=client_info[-1])
            if plain_text == FILE_TRANSFER_BULK_SIGNAL:
                receive_file_bulk(name=client_info[0], ip=ip_address, sock=sock, cipher=client_info[-1])
        else:
            host_disconnect_handler(self, sock, client_info[0], ip_address, is_server=True)

    # Handler for Client
    else:
        if data:
            print(f"[+] Received data from [{self.server_name}, {ip_address}] (encrypted): {data}")
            plain_text = decrypt(cipher=self.cipher, cipher_text=data)
            print(f"[+] Received data from [{self.server_name}, {ip_address}] (decrypted): {plain_text}")

            # File Transfer Handler
            if plain_text == FILE_TRANSFER_SIGNAL:
                receive_file(name=self.server_name, ip=ip_address, sock=sock, cipher=self.cipher)
            if plain_text == FILE_TRANSFER_BULK_SIGNAL:
                receive_file_bulk(name=self.server_name, ip=ip_address, sock=sock, cipher=self.cipher)
        else:
            host_disconnect_handler(self, sock, self.server_name, ip_address, is_server=False)


def send_file(name: str, ip: str, sock: socket.socket, cipher: CustomCipher):
    """
    Sends a file to the target host (in chunks) using
    a custom PSH(Send)/ACK protocol.

    @attention Chunk Size
        The chunk size is 1024 bytes; therefore,
        the sending host is sending 1024/16 = 64 blocks
        per chunk.

    @param name:
        A string representing the name of
        the target host

    @param ip:
        A string representing the IP address
        of the target host

    @param sock:
        A target socket object

    @param cipher:
        A CustomCipher object

    @return: None
    """
    if sock is None and cipher is None:
        return None

    # Prompt user for a file path (can be any format)
    input_path = input(TRANSFER_FILE_PATH_PROMPT)

    # Read file by block
    try:
        with open(input_path, 'rb') as file:
            print("=" * 160)
            print(f"[+] Now transferring the file to [{name}, {ip}] (in chunks)...")

            # Send a signal for File Transfer to the other host
            sock.send(encrypt(cipher, plain_text=FILE_TRANSFER_SIGNAL, verbose=False))
            print(f"[+] SIGNAL SENT: A signal has been sent to [{name}, {ip}] to initiate file transfer...")

            # Wait for ACK before proceeding
            sock.recv(1024)

            # Determine the total number of blocks from file size
            total_bytes = os.path.getsize(input_path)
            total_blocks = total_bytes // cipher.block_size
            sock.send(encrypt(cipher, plain_text=str(total_blocks), verbose=False))
            print(f"[+] File Size: {total_bytes} bytes")
            print(f"[+] Total Number of Blocks (to be sent): {total_blocks}")

            # Wait for ACK before proceeding
            sock.recv(1024)

            # Send the file name to target
            file_name = input_path.split("/")[-1]
            sock.send(encrypt(cipher, plain_text=file_name, verbose=False))
            print(f"[+] File parameters have been successfully sent to [{name}, {ip}]")

            # Wait for ACK before proceeding
            sock.recv(1024)

            # LOOP: Encrypt and send blocks in 1024 byte chunks, wait for ACK before proceeding
            blocks_sent = 0
            while True:
                chunk = file.read(1024)
                if not chunk:  # => End of file (EOF)
                    break

                encrypted_chunk = cipher.encrypt(plaintext=chunk, format=FORMAT_FILE, verbose=False)
                sock.sendall(encrypted_chunk)

                sock.recv(1024)  # => Wait for ACK

                blocks_sent += len(chunk) // cipher.block_size
                print(f"[+] Blocks {blocks_sent}/{total_blocks} has been successfully sent to and "
                      f"received by [{name}, {ip}]")

            # Send an EOF signal to end file transfer
            sock.send(encrypt(cipher, plain_text=END_OF_FILE, verbose=False))
            print(f"[+] OPERATION SUCCESSFUL: {file_name} has been successfully sent!")
            print("=" * 160)

    except (FileNotFoundError, IsADirectoryError):
        print("[+] READ FILE ERROR: File not found in the path provided ({})".format(input_path))
        return None


def receive_file(name: str, ip: str, sock: socket.socket, cipher: CustomCipher):
    """
    Receives a file from an initiating host (in chunks)
    using a custom PSH(Send)/ACK protocol.

    @attention Chunk Size:
        The chunk size is 1024 bytes; therefore,
        the receiving host is getting 1024/16 = 64 blocks
        per chunk.

    @param name:
        A string representing the name of the
        initiating host

    @param ip:
        A string representing the IP address of the
        initiating host

    @param sock:
        A socket object

    @param cipher:
        A CustomCipher object

    @return: None
    """
    print("=" * 160)
    print(f"[+] FILE TRANSFER: A host [{name}, {ip}] has initiated file transfer!")

    # Send ACK to synchronize with the other host
    sock.send(encrypt(cipher, plain_text=ACK, verbose=False))

    # Receive total number of blocks
    total_blocks = decrypt(cipher, cipher_text=sock.recv(1024), verbose=False)
    print(f"[+] Total Number of Blocks (to be received): {total_blocks}")

    # Send ACK to synchronize with the other host
    sock.send(encrypt(cipher, plain_text=ACK, verbose=False))

    # Receive File Name
    file_name = decrypt(cipher, cipher_text=sock.recv(1024), verbose=False)
    print(f"[+] Host [{name}, {ip}] is transferring the following file: {file_name}")

    # Create a Save Directory for the file ("data/received/host_ip")
    if not os.path.exists(SAVE_FILE_DIR.format(ip)):
        os.makedirs(SAVE_FILE_DIR.format(ip))
        print(f"[+] The following directory has been created: {SAVE_FILE_DIR.format(ip)}")

    # Send ACK to synchronize with the initiating host
    sock.send(encrypt(cipher, plain_text=ACK, verbose=False))

    # Define a new file path for the received file
    new_save_path = os.path.join(SAVE_FILE_DIR.format(ip), file_name)

    # LOOP: Receive and decrypt blocks in 1024 byte chunks, write to file, and send ACK
    blocks_received = 0
    with open(new_save_path, 'wb') as file:
        while True:
            encrypted_chunk = sock.recv(1024)
            decrypted_chunk = cipher.decrypt(ciphertext=encrypted_chunk,
                                             format=FORMAT_FILE,  # => Return as bytes
                                             verbose=False)
            if decrypted_chunk == b'EOF':
                break

            file.write(decrypted_chunk)

            # Send ACK back to receive the next chunk
            blocks_received += len(encrypted_chunk) // cipher.block_size
            print(f"[+] Successfully received blocks ({blocks_received}/{total_blocks}) "
                  f"from [{name}, {ip}]: {decrypted_chunk}\n")
            sock.send(encrypt(cipher, plain_text=ACK, verbose=False))

    print(f"[+] OPERATION COMPLETED: The file has been successfully saved to '{new_save_path}'")
    print("=" * 160)


def send_file_bulk(name: str, ip: str, sock: socket.socket, cipher: CustomCipher):
    """
    Sends a file to the target host (as a whole).

    @param name:
        A string representing the name of
        the target host

    @param ip:
        A string representing the IP address
        of the target host

    @param sock:
        A target socket object

    @param cipher:
        A CustomCipher object

    @return: None
    """
    if sock is None and cipher is None:
        return None

    # Prompt user for a file path (can be any file format)
    input_path = input(TRANSFER_FILE_PATH_PROMPT)

    try:
        with open(input_path, 'rb') as f:
            print("=" * 160)
            print(f"[+] Now transferring the file to [{name}, {ip}] (in bulk)...")

            # Read the file and perform bulk encryption
            file_data = f.read()
            encrypted_data = encrypt(cipher, plain_text=file_data, format=FORMAT_FILE, verbose=False)

            # Send a signal for bulk file transfer to the other host
            sock.send(encrypt(cipher, plain_text=FILE_TRANSFER_BULK_SIGNAL, verbose=False))
            print(f"[+] SIGNAL SENT: A signal has been sent to [{name}, {ip}] to initiate file transfer...")

            # Wait for ACK before proceeding
            sock.recv(1024)

            # Send the file name to target
            file_name = input_path.split("/")[-1]
            sock.send(encrypt(cipher, plain_text=file_name, verbose=False))

            # Wait for ACK before proceeding
            sock.recv(1024)

            # Send the payload size
            payload_size = len(encrypted_data)
            sock.sendall(payload_size.to_bytes(8, 'big'))
            print(f"[+] File Payload Size: {payload_size} bytes")
            print(f"[+] File parameters have been successfully sent to [{name}, {ip}]")

            # Wait for ACK before proceeding
            sock.recv(1024)

            # Send the payload in bulk
            sock.sendall(encrypted_data)
            print(f"[+] OPERATION COMPLETED: The file has been sent successfully to [{name}, {ip}]!")
            print("=" * 160)
    except (FileNotFoundError, IsADirectoryError):
        print("[+] READ FILE ERROR: File not found in the path provided ({})".format(input_path))
        return None


def receive_file_bulk(name: str, ip: str, sock: socket.socket, cipher: CustomCipher):
    """
    Receives a file from an initiating host (as a whole).

    @param name:
        A string representing the name of the
        initiating host

    @param ip:
        A string representing the IP address of the
        initiating host

    @param sock:
        A socket object

    @param cipher:
        A CustomCipher object

    @return: None
    """
    print("=" * 160)
    print(f"[+] FILE TRANSFER: A host [{name}, {ip}] has initiated file transfer!")

    # Send ACK to synchronize with the other host
    sock.send(encrypt(cipher, plain_text=ACK, verbose=False))

    # Receive File Name
    file_name = decrypt(cipher, cipher_text=sock.recv(1024), verbose=False)
    print(f"[+] Host [{name}, {ip}] is transferring the following file: {file_name}")

    # Create a Save Directory for the file ("data/received/host_ip")
    if not os.path.exists(SAVE_FILE_DIR.format(ip)):
        os.makedirs(SAVE_FILE_DIR.format(ip))
        print(f"[+] The following directory has been created: {SAVE_FILE_DIR.format(ip)}")

    # Send ACK to synchronize with the other host
    sock.send(encrypt(cipher, plain_text=ACK, verbose=False))

    # Receive the payload size
    file_size = int.from_bytes(sock.recv(8), 'big')
    print(f"[+] File payload size: {file_size} bytes")

    # Send ACK to synchronize with the other host
    sock.send(encrypt(cipher, plain_text=ACK, verbose=False))

    # Receive the payload in bulk
    received_data = b''
    while len(received_data) < file_size:
        data = sock.recv(1024)
        if not data:
            break
        received_data += data

    # Decrypt the payload and define a new save path for file
    decrypted_data = decrypt(cipher, cipher_text=received_data, format=FORMAT_BYTES, verbose=False)
    new_save_path = os.path.join(SAVE_FILE_DIR.format(ip), file_name)

    # Save the decrypted file
    write_to_file(new_save_path, decrypted_data)
    print("=" * 160)
