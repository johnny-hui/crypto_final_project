# GETOPTS CONSTANTS
MIN_PORT_VALUE = 1
MAX_PORT_VALUE = 65536
INVALID_SRC_IP_ARG_ERROR = ("[+] INIT ERROR: Invalid format for the source IP address was provided "
                            "(-s option): {}")
INVALID_SRC_PORT_RANGE = ("[+] INIT ERROR: The value provided for source port (-p option) is not "
                          "valid: (not between 1 and 65535)")
INVALID_FORMAT_SRC_PORT_ARG_ERROR = "[+] INIT ERROR: Invalid format provided for the source port (-p option): {}"


# CIPHER CONFIG CONSTANTS
BLOCK_SIZE = 16  # 16 bytes
ROUNDS = 16
DEFAULT_ROUND_KEYS = [
    0xdddddddddddddddd, 0xeeeeeeeeeeeeeeee, 0xaaaaaaaaaaaaaaaa, 0xdddddddddddddddd,
    0xbbbbbbbbbbbbbbbb, 0xeeeeeeeeeeeeeeee, 0xeeeeeeeeeeeeeeee, 0xffffffffffffffff
]
ECB = "ecb"
CBC = "cbc"


# CIPHER INIT CONSTANTS
CIPHER_INIT_MSG = "[+] Initializing cipher..."
CIPHER_INIT_SUCCESS_MSG = "[+] The cipher has been successfully initialized!"
CIPHER_INIT_CONFIG_TITLE = "Cipher Settings"
CIPHER_INIT_CONFIG_COLUMNS = ["Setting", "Value"]
CIPHER_INIT_CONFIG_ATTRIBUTES = [
    "Mode", "Number of Rounds", "Block Size (bytes)", "Main Key",
    "Subkey Generation", "Initialization Vector(IV)", "Sub-keys"
]
GET_SUBKEY_USER_PROMPT = "[+] Enter 1 (to provide own sub-keys); Enter 2 (to use default sub-keys)"


# SERVER/CLIENT INIT CONSTANTS
INIT_SERVER_MSG = "[+] Now initializing the server..."
INIT_CLIENT_MSG = "[+] Now initializing the client..."
INIT_SUCCESS_MSG = "[+] Initialization Successful!"


# MODE CONSTANTS
MODE_SERVER = "SERVER"
MODE_CLIENT = "CLIENT"
MODE_PLAYGROUND = "PLAYGROUND"


# CIPHER PLAYGROUND CONSTANTS
PLAYGROUND_MIN_MENU_ITEM_VALUE = 1
PLAYGROUND_MAX_MENU_ITEM_VALUE = 9
USER_MENU_TITLE = "Menu Options"
USER_MENU_COLUMNS = ["Option", "Command"]
USER_MENU_OPTIONS_LIST = [
    ["1", "Perform Encryption"],
    ["2", "Perform Decryption"],
    ["3", "Perform Avalanche Analysis"],
    ["4", "Change Mode"],
    ["5", "Change Main Key"],
    ["6", "Regenerate Sub-keys"],
    ["7", "View Cipher Settings"],
    ["8", "View Pending Operations"],
    ["9", "Close Application"],
]
USER_INPUT_PROMPT = "[+] Select a menu option: "
INVALID_MENU_SELECTION = "[+] MENU SELECTION: Please enter a valid menu option ({} to {}): "
MENU_ACTION_START_MSG = "\n[+] ACTION SELECTED: Now performing menu item {}..."
INVALID_INPUT_MENU_ERROR = "[+] ERROR: Invalid input was provided to menu: {}"
PENDING_OP_TITLE = "Pending Operations (Decryption)"
PENDING_OP_COLUMNS = ["Format", "Mode", "Encrypted Payload", "Initialization Vector (IV)"]
FORMAT_USER_INPUT = "USER_INPUT"
FORMAT_TEXT_FILE = "TEXT"   # => Path to file
FORMAT_PICTURE = "PICTURE"  # => Path to file
FORMAT_AVALANCHE = "AVALANCHE"


# CLIENT/SERVER MENU CONSTANTS
CLIENT_MIN_MENU_ITEM_VALUE = 1
CLIENT_MAX_MENU_ITEM_VALUE = 5
SERVER_MIN_MENU_ITEM_VALUE = 1
SERVER_MAX_MENU_ITEM_VALUE = 4
MENU_TITLE = "Menu Options"
MENU_FIELD_OPTION = "Option"
MENU_FIELD_DESC = "Command"
INPUT_PROMPT = "[+] Select a menu option: "
CLIENT_MENU_OPTIONS_LIST = [
    ["1", "Connect to a Server"],
    ["2", "View Current Connection"],
    ["3", "Select Cipher Mode"],
    ["4", "Cipher Playground"],
    ["5", "Disconnect (Close Application)"]
]
SERVER_MENU_OPTIONS_LIST = [
    ["1", "Send Message to a Client"],
    ["2", "View Current Connections"],
    ["3", "Cipher Playground"],
    ["4", "Disconnect (Close Application)"]
]
SEND_MESSAGE_OPTION = ["1", "Send Message to Server"]
USER_INPUT_START_MSG = "[+] User input (menu) thread has started!"
USER_INPUT_THREAD_NAME = "user_input_menu_thread"
USER_MENU_THREAD_TERMINATE = "[+] THREAD TERMINATION: User menu thread has been successfully terminated!"
SELECT_ONE_SECOND_TIMEOUT = 1
CIPHER_MODE_PROMPT = "[+] CHANGE CIPHER MODE: Enter 1 - CBC; Enter 2 - ECB; (or Enter 0 to quit) "


# USER MENU - REGENERATE SUBKEYS CONSTANTS
REGENERATE_SUBKEY_OPTIONS_PROMPT = ("[+] Enter 1 to enter own main key; Enter 2 to generate main key from "
                                    "an elliptic curve (brainpoolP256r1); (or Enter 0 to quit) ")
CHANGE_KEY_PROMPT = "[+] Please enter a new key ({} characters) for encryption: "
REGENERATE_SUBKEY_PROMPT = "[+] Please enter an option to generate new sub-keys: "
REGENERATE_SUBKEY_OPTIONS = [
    "[+] Enter 0 - Exit",
    "[+] Enter 1 - Generate Using Main Key",
    "[+] Enter 2 - Use Default Subkeys",
    "[+] Enter 3 - Provide Own Subkeys",
]


# USER MENU - ENCRYPTION CONSTANTS
USER_ENCRYPT_OPTIONS_PROMPT = "[+] Please select an option for encryption: "
USER_ENCRYPT_OPTIONS = [
    "[+] Enter 0 - Exit",
    "[+] Enter 1 - Encrypt User Input",
    "[+] Enter 2 - Encrypt a Text File",
    "[+] Enter 3 - Encrypt a Picture (Bitmap only)",
]
USER_ENCRYPT_INPUT_PROMPT = "[+] Please enter a plaintext string to encrypt: "
USER_ENCRYPT_FILE_PATH_PROMPT = "[+] Please enter the path of the text file to encrypt: "
USER_ENCRYPT_IMAGE_PATH_PROMPT = "[+] Please enter the path of the image file to encrypt: "


# USER MENU - DECRYPTION CONSTANTS
USER_DECRYPT_OPTIONS_PROMPT = "[+] Please select an option for decryption: "
USER_DECRYPT_OPTIONS = [
    "[+] Enter 0 - Exit",
    "[+] Enter 1 - Decrypt User Input",
    "[+] Enter 2 - Decrypt a Text File",
    "[+] Enter 3 - Decrypt a Picture (Bitmap only)"
]


# AVALANCHE ANALYSIS CONSTANTS
AVALANCHE_ANALYSIS_SPAC_PROMPT = ("[+] AVALANCHE ANALYSIS: Enter 1 to provide own plaintext message (64-bit or 8 char "
                                  "only; Enter 2 to use generated plaintext message; or (Enter 0 to quit): ")
AVALANCHE_ANALYSIS_SKAC_PROMPT = ("[+] AVALANCHE ANALYSIS: Enter 1 to provide own key (128-bit or 16 char) "
                                  "only; Enter 2 to use a randomly generated a key (from an Elliptic Curve: "
                                  "brainpoolP256r1); or (Enter 0 to quit): ")
AVALANCHE_ANALYSIS_USER_INPUT_KEY = "[+] Enter a key ({} characters only): "
AVALANCHE_ANALYSIS_USER_INPUT = "[+] Enter a plaintext message ({} characters only): "
AVALANCHE_TASK_SPAC_TITLE = "Encryption {} Bit Change in Plaintext (SPAC) - [Starting from MSB]"
AVALANCHE_TASK_SKAC_TITLE = ("Encrypting Ciphertext after {} Bit Changes in Key (SKAC) - {} 4th Bit Position "
                             "[Starting from MSB]")
NO_SUBKEYS_ENCRYPT_MSG = "[+] ENCRYPT ERROR: There are no sub-keys provided!"
NO_SUBKEYS_DECRYPT_MSG = "[+] DECRYPT ERROR: There are no sub-keys provided!"
GRAPH_LABEL_SPAC = ["1 Bit Change in Plaintext", "2 Bit Change in Plaintext", "3 Bit Change in Plaintext",
                    "4 Bit Change in Plaintext", "5 Bit Change in Plaintext", "6 Bit Change in Plaintext",
                    "7 Bit Change in Plaintext", "8 Bit Change in Plaintext", "9 Bit Change in Plaintext",
                    "10 Bit Change in Plaintext"]
GRAPH_LABEL_SKAC = ["1 Bit Change in Key", "2 Bit Change in Key", "3 Bit Change in Key",
                    "4 Bit Change in Key", "5 Bit Change in Key", "6 Bit Change in Key",
                    "7 Bit Change in Key", "8 Bit Change in Key", "9 Bit Change in Key",
                    "10 Bit Change in Key"]
SAVE_GRAPH_DIR = "data/graphs/{}"


# CONNECTION INFO CONSTANTS
CONNECTION_INFO_TITLE = "Current Connections"
CONNECTION_INFO_FIELD_NAME = "Name"
CONNECTION_INFO_FIELD_IP = "IP Address"
CONNECTION_INFO_FIELD_CIPHER_MODE = "Encryption Mode"
CONNECTION_INFO_FIELD_SECRET = "Shared Secret"
CONNECTION_INFO_FIELD_IV = "Initialization Vector (IV)"


# SEND MESSAGE CONSTANTS
SERVER_SELECT_CLIENT_PROMPT = "\n[+] Select a specific client to send a message to (enter a number from {} to {}): "


# OTHER CONSTANTS
OP_ENCRYPT = "ENCRYPTION"
OP_DECRYPT = "DECRYPTION"
