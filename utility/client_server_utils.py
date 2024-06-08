import ipaddress
import pickle
import secrets
import socket
import time
from typing import TextIO
from prettytable import PrettyTable
from tinyec.ec import Inf
from models.CustomCipher import CustomCipher
from utility.constants import (MENU_TITLE, MENU_FIELD_OPTION, MENU_FIELD_DESC, CLIENT_MENU_OPTIONS_LIST,
                               SEND_MESSAGE_OPTION, SERVER_MENU_OPTIONS_LIST, INVALID_MENU_SELECTION,
                               MENU_ACTION_START_MSG, INVALID_INPUT_MENU_ERROR, MIN_PORT_VALUE,
                               MAX_PORT_VALUE, CONNECTION_INFO_FIELD_NAME, CONNECTION_INFO_FIELD_IP,
                               CONNECTION_INFO_FIELD_SECRET, CONNECTION_INFO_FIELD_IV, CONNECTION_INFO_TITLE, CBC,
                               BLOCK_SIZE, CONNECTION_INFO_FIELD_CIPHER_MODE)
from utility.ec_keys_utils import derive_shared_secret


def encrypt(cipher: CustomCipher, plain_text: str):
    """
    Uses the CustomCipher to encrypt plaintext with a 32-byte
    (256-bit) shared secret key derived from ECDH.

    @param cipher:
        A CustomCipher object

    @param plain_text:
        A string representing the plaintext to
        be encrypted

    @return: cipher_text
        The encrypted ciphertext (string)
    """
    ciphertext = cipher.encrypt(plain_text)
    return ciphertext


def decrypt(cipher: CustomCipher, cipher_text: bytes):
    """
    Uses the CustomCipher to decrypt ciphertext with a 32-byte
    (256-bit) shared secret key derived from ECDH.

    @param cipher:
        A CustomCipher object

    @param cipher_text:
        An array of bytes containing encrypted data

    @return: plain_text
        The decrypted plaintext (string)
    """
    plain_text = cipher.decrypt(cipher_text)
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
        menu.add_row(SEND_MESSAGE_OPTION)
        for item in CLIENT_MENU_OPTIONS_LIST[1:]:
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
    except ValueError as e:
        print(INVALID_INPUT_MENU_ERROR.format(e))
        print(INVALID_MENU_SELECTION.format(min_num_options, max_num_options))
    except TypeError as e:
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
        print("[+] KEY EXCHANGE: Now exchanging keys with the server...")

        # Bind class attributes
        self.is_connected = True
        self.server_socket = sock
        self.fd_list.append(sock)

        # Receive cipher mode from server
        mode = sock.recv(1024).decode()
        print(f"[+] MODE RECEIVED: The encryption mode for this session is {mode.upper()}")

        # Receive IV from server (if CBC)
        if mode == CBC:
            iv = sock.recv(1024)
            print(f"[+] IV RECEIVED: The initialization vector (IV) has been received from the server ({iv.hex()})")

        # Send Public Key to Server
        serialized_key = pickle.dumps(self.pub_key)
        sock.sendall(serialized_key)

        # Receive Public Key from Server
        serialized_server_pub_key = sock.recv(4096)
        server_pub_key = pickle.loads(serialized_server_pub_key)

        # Derive the shared secret (print in hex)
        shared_secret = derive_shared_secret(self.pvt_key, server_pub_key)
        self.shared_secret = shared_secret.hex()
        print(f"[+] KEY EXCHANGE SUCCESS: A shared secret has been derived for the current "
              f"session ({self.shared_secret}) | Number of Bytes = {len(shared_secret)}")

        # Derive CustomCipher Object (and save IV there)
        if mode == CBC:
            self.cipher = CustomCipher(key=shared_secret, mode=mode, iv=iv)
        else:
            self.cipher = CustomCipher(key=shared_secret, mode=mode)

        # Receive name of server
        self.server_name = decrypt(self.cipher, cipher_text=sock.recv(1024))

        # Send name to server
        sock.send(encrypt(self.cipher, self.name))
        print(f"[+] CONNECTION SUCCESS: A secure session with {self.server_name} has been established!")
    except socket.error as e:
        print(f"[+] CONNECTION FAILED: Failed to connect to target server ({e}); please try again.")


def exchange_public_keys(pub_key: Inf, client_sock: socket.socket):
    """
    Performs the ECDH public key exchange process.

    @attention Use Case:
        Only used by Server class (client has their own protocol)

    @param pub_key:
        The public key to send over

    @param client_sock:
        The client's socket

    @return: client_pub_key
    """
    print("[+] KEY EXCHANGE: Now exchanging keys with new client...")

    # Receive Client's Public Key
    serialized_client_pub_key = client_sock.recv(4096)
    client_pub_key = pickle.loads(serialized_client_pub_key)

    # Send over the public key to the client
    serialized_key = pickle.dumps(pub_key)
    client_sock.sendall(serialized_key)
    return client_pub_key


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
    print(f"[+] NEW CONNECTION: Accepted a client connection from ({client_address[0]}, {client_address[1]})")

    # Send cipher mode to the client
    client_socket.send(self.cipher_mode.encode())

    # Generate and send client IV (if CBC)
    if self.cipher_mode == CBC:
        client_iv = secrets.token_bytes(BLOCK_SIZE)
        time.sleep(0.5)
        client_socket.send(client_iv)
        print(f"[+] IV GENERATED: An initialization vector (IV) has been generated for this client ({client_iv.hex()})")

    # Exchange public keys with the client
    self.fd_list.append(client_socket)
    client_pub_key = exchange_public_keys(self.pub_key, client_socket)

    # Derive the shared secret and compress for AES
    shared_secret = derive_shared_secret(self.pvt_key, client_pub_key)
    compressed_shared_secret = shared_secret.hex()
    print(f"[+] KEY EXCHANGE SUCCESS: A shared secret has been derived for the current "
          f"session ({compressed_shared_secret}) | Number of Bytes = {len(shared_secret)}")

    # Derive CustomCipher Object (according to mode)
    if self.cipher_mode == CBC:
        cipher = CustomCipher(key=shared_secret, mode=self.cipher_mode, iv=client_iv)
    else:
        cipher = CustomCipher(key=shared_secret, mode=self.cipher_mode)

    # Send information to the client using CustomCipher (in bytes)
    client_socket.send(encrypt(cipher, self.name))

    # Receive name from the client (encrypted)
    name = decrypt(cipher, cipher_text=client_socket.recv(1024))

    # Update client dictionary with the new client (include CustomCipher)
    self.client_dict[client_address[0]] = [name, compressed_shared_secret, client_iv, self.cipher_mode, cipher]
    print(f"[+] CONNECTION SUCCESS: A secure session with {name} has been established!")


def send_message(sock: socket.socket, shared_secret: bytes, IV: bytes):
    """
    Prompts user for a plaintext message, encrypts it
    and sends it to a target socket.

    @param sock:
        The target socket

    @param shared_secret:
        Bytes of the shared secret key

    @param IV:
        A randomly generated n-bytes for initialization vector (IV)

    @return: None
    """
    if sock is not None:
        ip = sock.getpeername()[0]
        message = input(f"[+] Enter a message to send to ({ip}): ").encode()

        cipher_text = encrypt(message, shared_secret, IV)
        sock.send(cipher_text)

        print("[+] Your message has been successfully sent!")


def receive_data(self: object, sock: socket.socket, is_server: bool = False):
    """
    Handles the receiving of data (or disconnections) from a socket.

    @param self:
        A reference to the calling class object

    @param sock:
        A socket object

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
        client_info = self.client_dict[ip_address]  # => Get specific client secret {IP: [name, shared_secret, IV]}
        if data:
            print(f"[+] Received data from [{client_info[0]}, {ip_address}] (encrypted): {data.hex()}")
            plain_text = decrypt(data, client_info[1], client_info[2])
            print(f"[+] Received data from [{client_info[0]}, {ip_address}] (decrypted): {plain_text.decode()}")
        else:
            print(f"[+] Connection closed by ({client_info[0]}, {ip_address})")
            del self.client_dict[ip_address]
            self.fd_list.remove(sock)
            sock.close()

    # Handler for Client
    else:
        if data:
            print(f"[+] Received data from [{self.server_name}, {ip_address}] (encrypted): {data.hex()}")
            plain_text = decrypt(data, self.shared_secret, self.iv)
            print(f"[+] Received data from [{self.server_name}, {ip_address}] (decrypted): {plain_text.decode()}")
        else:
            print(f"[+] Connection closed by ({self.server_name}, {ip_address})")
            self.server_socket, self.server_name, self.shared_secret = None, None, None
            self.fd_list.remove(sock)
            sock.close()
