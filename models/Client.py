import select
import sys
import threading
from utility.client_server_utils import (display_menu, get_user_menu_option, send_message, connect_to_server,
                                         receive_data, view_current_connections, close_application)
from utility.constants import (INPUT_PROMPT, PLAYGROUND_MIN_MENU_ITEM_VALUE, PLAYGROUND_MAX_MENU_ITEM_VALUE,
                               INIT_CLIENT_MSG, INIT_SUCCESS_MSG, MODE_CLIENT, USER_INPUT_THREAD_NAME,
                               USER_INPUT_START_MSG, USER_MENU_THREAD_TERMINATE, SELECT_ONE_SECOND_TIMEOUT,
                               CLIENT_MIN_MENU_ITEM_VALUE, CLIENT_MAX_MENU_ITEM_VALUE)
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
        display_menu(self.is_connected)
        print(INPUT_PROMPT)

        while not self.terminate:
            readable, _, _ = select.select(inputs, [], [])

            # Get User Command from the Menu and perform the task
            for fd in readable:
                if fd == sys.stdin:
                    command = get_user_menu_option(fd, CLIENT_MIN_MENU_ITEM_VALUE, CLIENT_MAX_MENU_ITEM_VALUE)

                    if command == 1:
                        if self.is_connected and self.server_socket is not None:
                            send_message(self.server_socket, self.shared_secret, self.iv)
                        else:
                            connect_to_server(self)

                    if command == 2:
                        view_current_connections(self)

                    if command == 3:
                        print("CIPHER PLAYGROUND")

                    if command == 4:
                        close_application(self)
                        print(USER_MENU_THREAD_TERMINATE)
                        return None

                display_menu(self.is_connected)
                print(INPUT_PROMPT)
