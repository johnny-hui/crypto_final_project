import select
import sys
import threading

from utility.cipher_utils import get_user_command_option
from utility.client_server_utils import accept_new_connection_handler, display_menu, receive_data, get_user_menu_option, \
    close_application, view_current_connections, send_message
from utility.constants import INIT_SERVER_MSG, INIT_SUCCESS_MSG, MODE_SERVER, INPUT_PROMPT, USER_INPUT_THREAD_NAME, \
    USER_INPUT_START_MSG, USER_MENU_THREAD_TERMINATE, \
    SELECT_ONE_SECOND_TIMEOUT, SERVER_SELECT_CLIENT_PROMPT, CBC, CIPHER_MODE_PROMPT, ECB, SERVER_MAX_MENU_ITEM_VALUE, \
    SERVER_MIN_MENU_ITEM_VALUE
from utility.ec_keys_utils import generate_keys
from utility.init import parse_arguments, initialize_socket


class Server:
    """A class representing the server

    @attention: Design Decision
        Server cannot connect to other clients or servers
        (only accept connections)

    Attributes:
        ip - The ip address
        port - The port number
        name - The name of the server
        own_socket - The socket object for the server
        pvt_key - The private key generated by ECDH (via. brainpoolP256r1)
        pub_key - The public key generated by ECDH (via. brainpoolP256r1)
        fd_list - A list of file descriptors to monitor (using select() function)
        client_dict - A dictionary containing information about each connected client{IP: (name, shared secret key, IV)}
        cipher_mode - A string representing the cipher mode (default=CBC)
        terminate - A boolean flag that determines if the server should terminate
    """
    def __init__(self):
        """
        A constructor for a Server class object.
        """
        print(INIT_SERVER_MSG)
        self.name, self.ip, self.port = parse_arguments(is_server=True)
        self.own_socket = initialize_socket(self.ip, self.port)
        self.pvt_key, self.pub_key = generate_keys(mode=MODE_SERVER)
        self.fd_list = [self.own_socket]  # => Monitored by select()
        self.client_dict = {}  # Format {IP: [name, shared_secret, IV, cipher mode, cipher object]}
        self.cipher_mode = CBC  # Default = CBC
        self.terminate = False
        print(INIT_SUCCESS_MSG)

    def start(self):
        """
        Starts the server and monitors any incoming connections
        and messages from existing clients.

        @return: None
        """
        self.__start_user_menu_thread()

        while self.terminate is False:
            readable, _, _ = select.select(self.fd_list, [], [], SELECT_ONE_SECOND_TIMEOUT)

            for sock in readable:
                if sock is self.own_socket:
                    accept_new_connection_handler(self, sock)
                    display_menu(is_server=True)
                    print(INPUT_PROMPT)
                    # TODO: Print out the public keys when exchanging
                else:
                    receive_data(self, sock, is_server=True)

    def __start_user_menu_thread(self):
        """
        Starts a thread for handling user input
        for the menu.

        @return: None
        """
        input_thread = threading.Thread(target=self.__menu, name=USER_INPUT_THREAD_NAME)
        input_thread.start()
        print(USER_INPUT_START_MSG)

    def __menu(self):
        """
        Displays the menu and handles user input
        using select().

        @return: None
        """
        inputs = [sys.stdin]
        print("=" * 80)
        display_menu(is_server=True)
        print(INPUT_PROMPT)

        while not self.terminate:
            readable, _, _ = select.select(inputs, [], [])

            # Get User Command from the Menu and perform the task
            for fd in readable:
                if fd == sys.stdin:
                    command = get_user_menu_option(fd, SERVER_MIN_MENU_ITEM_VALUE, SERVER_MAX_MENU_ITEM_VALUE)

                    if command == 1:
                        client_sock, cipher = self.__get_specific_client()
                        send_message(client_sock, cipher)

                    if command == 2:
                        view_current_connections(self, is_server=True)

                    if command == 3:
                        self.__change_cipher_mode()

                    if command == 4:
                        print("CIPHER PLAYGROUND")  # Integrate this into UserViewModel class -> Playground class??

                    if command == 5:
                        close_application(self)
                        print(USER_MENU_THREAD_TERMINATE)
                        return None

                display_menu(is_server=True)
                print(INPUT_PROMPT)

    def __change_cipher_mode(self):
        """
        This function allows the server to change
        to a specific cipher mode.
        @return: None
        """
        print(f"[+] CURRENT CIPHER MODE: {self.cipher_mode.upper()}")
        option = get_user_command_option(msg=CIPHER_MODE_PROMPT, opt_range=tuple(range(3)))
        if option == 0:
            return None
        if option == 1:
            self.cipher_mode = CBC
        if option == 2:
            self.cipher_mode = ECB
        print(f"[+] OPERATION SUCCESSFUL: The cipher mode has been changed to {self.cipher_mode.upper()}")

    def __get_specific_client(self):
        """
        Prompts user to choose a specific client to
        send a message to.

        @return: tuple(fd, shared_secret, iv)
            A tuple containing the client socket, shared secret and
            the initialization vector
        """
        if len(self.fd_list) > 1:
            # Print current peers
            view_current_connections(self, is_server=True)

            while True:
                try:
                    # Prompt user selection for a specific client
                    client_index = int(input(SERVER_SELECT_CLIENT_PROMPT.format(1, len(self.client_dict))))
                    while client_index not in range(1, (len(self.client_dict) + 1)):
                        print("[+] ERROR: Invalid selection range; please enter again.")
                        client_index = int(input(SERVER_SELECT_CLIENT_PROMPT.format(1, len(self.client_dict))))

                    # Get information of the client (from dictionary)
                    ip, info = list(self.client_dict.items())[client_index - 1]
                    cipher = info[-1]

                    # Iterate over the list of sockets and find the corresponding one
                    for socket in self.fd_list[1:]:
                        if socket.getpeername()[0] == ip:
                            return socket, cipher

                except ValueError as e:
                    print(f"[+] ERROR: An invalid selection provided ({e}); please enter again.")
                except TypeError as e:
                    print(f"[+] ERROR: An invalid selection provided ({e}); please enter again.")
        else:
            print("[+] ERROR: There are currently no connected clients to send message!")
            return None, None, None
