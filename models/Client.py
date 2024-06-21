import select
import sys
import threading
from models.CipherPlayground import CipherPlayground
from utility.cipher_utils import get_user_command_option
from utility.client_server_utils import (display_menu, get_user_menu_option, send_message, connect_to_server,
                                         receive_data, view_current_connections, close_application, send_file,
                                         send_file_bulk)
from utility.constants import (INPUT_PROMPT, INIT_CLIENT_MSG, INIT_SUCCESS_MSG, MODE_CLIENT, USER_INPUT_THREAD_NAME,
                               USER_INPUT_START_MSG, USER_MENU_THREAD_TERMINATE, SELECT_ONE_SECOND_TIMEOUT,
                               CLIENT_MIN_MENU_ITEM_VALUE, CLIENT_MAX_MENU_ITEM_VALUE, CBC, CIPHER_MODE_PROMPT, ECB,
                               SEND_FILE_MODE_PROMPT)
from utility.ec_keys_utils import generate_keys
from utility.init import parse_arguments


class Client:
    """A class representing the client

    @attention: Design Decision
        Client can only connect to a server and not to other clients
        (i.e., this class does not listen for incoming connections)

    Attributes:
        name - The name of the client
        pvt_key - The private key generated by ECDH (via. brainpoolP256r1)
        pub_key - The public key generated by ECDH (via. brainpoolP256r1)
        own_socket - The socket object for the client
        fd_list - A list of file descriptors to monitor (using select() function)
        server_socket - The socket object for the server
        server_name - The name of the server
        cipher = A reference to CustomCipher object (default=None)
        cipher_mode - A string representing the cipher mode (default=CBC)
        shared_secret - The shared secret with the server (generated by ECDH key exchange)
        is_connected - A boolean indicating if the client is connected
        terminate - A boolean flag that determines if the server should terminate
    """

    def __init__(self):
        """
        A constructor for a Client class object.
        """
        print(INIT_CLIENT_MSG)
        self.name, _, _ = parse_arguments(is_server=False)
        self.pvt_key, self.pub_key = generate_keys(mode=MODE_CLIENT)
        self.fd_list = []  # => Monitored by select()
        self.server_socket, self.server_name = None, None
        self.cipher = None
        self.cipher_mode = CBC  # Default = CBC
        self.shared_secret = None
        self.is_connected = False
        self.terminate = False
        print(INIT_SUCCESS_MSG)

    def start(self):
        """
        Starts the client and monitors any incoming data from
        a target server.

        @return: None
        """
        self.__start_user_menu_thread()

        while not self.terminate:
            readable, _, _ = select.select(self.fd_list, [], [], SELECT_ONE_SECOND_TIMEOUT)

            for fd in readable:
                if fd is self.server_socket:
                    receive_data(self, fd)

    def __menu(self):
        """
        Displays the menu and handles user input
        using select().

        @return: None
        """
        inputs = [sys.stdin]
        print("=" * 80)
        display_menu(self.is_connected)
        print(INPUT_PROMPT)

        while not self.terminate:
            readable, _, _ = select.select(inputs, [], [])

            # Get User Command from the Menu and perform the task
            for fd in readable:
                if fd == sys.stdin:
                    command = get_user_menu_option(fd, CLIENT_MIN_MENU_ITEM_VALUE, CLIENT_MAX_MENU_ITEM_VALUE)
                    self.__handle_command(command)

    def __start_user_menu_thread(self):
        """
        Starts a thread for handling user input
        for the menu.

        @return: None
        """
        input_thread = threading.Thread(target=self.__menu, name=USER_INPUT_THREAD_NAME)
        input_thread.start()
        print(USER_INPUT_START_MSG)

    def __handle_command(self, command: int):
        """
        Handles and performs user menu command options
        for the Client.

        @param command:
            An integer representing the menu option
            to be performed

        @return: None
        """

        def send_file_to_server():
            send_type = get_user_command_option(opt_range=tuple(range(3)), msg=SEND_FILE_MODE_PROMPT)
            if send_type == 0:  # To quit
                return None
            else:
                self.fd_list.remove(self.server_socket)
                if send_type == 1:  # Send in chunks
                    send_file(name=self.server_name, ip=self.server_socket.getpeername()[0],
                              sock=self.server_socket, cipher=self.cipher)
                elif send_type == 2:  # Send in bulk (as a whole)
                    send_file_bulk(name=self.server_name, ip=self.server_socket.getpeername()[0],
                                   sock=self.server_socket, cipher=self.cipher)
                self.fd_list.append(self.server_socket)

        def terminate_application():
            close_application(self)
            print(USER_MENU_THREAD_TERMINATE)

        def perform_post_action_steps():
            # If terminate application, don't print the menu again
            if (self.is_connected and command == 6) or (not self.is_connected and command == 5):
                return None
            display_menu(self.is_connected)
            print(INPUT_PROMPT)

        # Map command to functions for when the client is connected or not connected
        actions_when_connected = {
            1: lambda: send_message(self.server_socket, self.cipher),
            2: lambda: send_file_to_server(),
            3: lambda: view_current_connections(self),
            4: lambda: self.__change_cipher_mode(),
            5: lambda: CipherPlayground().start(),
            6: lambda: terminate_application(),
        }

        actions_when_not_connected = {
            1: lambda: connect_to_server(self),
            2: lambda: view_current_connections(self),
            3: lambda: self.__change_cipher_mode(),
            4: lambda: CipherPlayground().start(),
            5: lambda: terminate_application(),
        }

        # Get action corresponding to the command
        if self.is_connected and self.server_socket is not None:
            action = actions_when_connected.get(command)
        else:
            action = actions_when_not_connected.get(command)

        # Perform the action
        if action:
            action()
            perform_post_action_steps()

    def __change_cipher_mode(self):
        """
        This function allows the client to change to a
        specific cipher mode (similar to cipher suite).

        @return: None
        """
        print(f"[+] CURRENT CIPHER MODE: {self.cipher_mode.upper()}")

        if self.is_connected:
            print("[+] CHANGE CIPHER MODE ERROR: Cannot change cipher mode while connected to a server!")
            return None

        option = get_user_command_option(msg=CIPHER_MODE_PROMPT, opt_range=tuple(range(3)))
        if option == 0:
            return None
        if option == 1:
            self.cipher_mode = CBC
        if option == 2:
            self.cipher_mode = ECB
        print(f"[+] OPERATION SUCCESSFUL: The cipher mode has been changed to {self.cipher_mode.upper()}")
