'''

##############################
#
# NOT FOR PRODUCTION USE
#
# REFERENCE CODE ONLY
#
# USE AT YOUR OWN RISK!!!!!!
#
##############################

'''
import json
import os.path
import getpass

# Import Yubico Libs
import yubihsm.exceptions

from yubihsm import YubiHsm
from yubihsm.objects import AuthenticationKey, AsymmetricKey
from yubihsm.defs import CAPABILITY, ALGORITHM

# Supporting Class

class bcolors:
    WARNING = '\033[93m'
    BOLD = '\033[1m'
    ENDC = '\033[0m'
    Red = '\033[91m'
    Green = '\033[92m'
    Blue = '\033[94m'
    Cyan = '\033[96m'
    White = '\033[97m'
    Yellow = '\033[93m'
    Magenta = '\033[95m'
    Grey = '\033[90m'
    Black = '\033[90m'
    Default = '\033[99m'


objHSM = ""

'''
authid = 1
serverip = "192.168.2.118"
port = "12345"
password = "password"
hsm = YubiHsm.connect("http://{0}:{1}/connector/api".format(serverip, port))
session = hsm.create_session_derived(authid, password)
'''

def _session(authid=1, serverip="127.0.0.1", port="12345", password="password"):
    '''
    Create an authenticated session to the YubiHSM connector
    '''
    global objHSM

    try:
        hsm = YubiHsm.connect("http://{0}:{1}/connector/api".format(serverip, port))
        session = hsm.create_session_derived(authid, password)
    except yubihsm.exceptions.YubiHsmAuthenticationError:
        message = bcolors.Red + "Login failed" + bcolors.ENDC
        login(message)
    except yubihsm.exceptions.YubiHsmConnectionError:
        message = bcolors.Red + "No route to host" + bcolors.ENDC
        login(message)
    except yubihsm.exceptions.YubiHsmDeviceError:
        message = bcolors.Red + "Login faile 2" + bcolors.ENDC
        login(message)

    objHSM = {"hsm": hsm, "session": session}
    return True

def reset_hardware():
    '''
    Reset the YubiHSM to factory defaults
    '''
    session = objHSM['session']
    try:
        session.reset_device()
        message = bcolors.Green + " Device has been reset. You must login again."
        login()
    except yubihsm.exceptions.YubiHsmInvalidResponseError:
        message = bcolors.Red + " Incorrect MAC " + bcolors.ENDC
        menu(message)
    return True

def list_objects():
    '''
    List all the objects for a domain
    '''
    session = objHSM['session']

    objslist = session.list_objects()

    for objlist in objslist:
        obj = objlist.get_info()

        print ("ID: " + str(obj.id))
        print ("Label: " + obj.label)
        print ("Domains: " + str(obj.domains))
        print ("Type: " + str(obj.object_type))
        print ("----------------------------")
    
    print("Press C to continue or Q to exit")
    choice = input().lower()
    if choice == "c":
        menu()
    elif choice == "q":
        exit()

def deviceinfo():
    '''
    Get the device information
    '''
    hsm = objHSM['hsm']
    print(hsm.get_device_info().serial)
    print("")
    print("Press C to continue or Q to exit")
    choice = input().lower()
    if choice == "c":
        menu()
    elif choice == "q":
        exit()

def create_asymm():
    os.system('clear')
    print (bcolors.Yellow + "***********   Create Asymmetric Key Pair for signing operations  ***************" + bcolors.ENDC)
    print ("What would you like for an object ID (0 = auto creates):")
    object_id = int(input())
    print ("What domains should this be assigned to:")
    domains = int(input())
    print ("What label would you like to set:")
    # TODO: Needs to be no longer than 40 bytes
    label = input()

    capabilities = CAPABILITY.SIGN_ECDSA
    algorithm = ALGORITHM.EC_P256

    try:
        session = objHSM['session']
        key = AsymmetricKey.generate(session, object_id, label, domains, capabilities, algorithm)
    except yubihsm.exceptions.YubiHsmDeviceError:
        print("Error")

    print("Created new Asymmetric key pair")
    print("Name: " + label)
    print("ID: " + str(key.id))
    print("")
    print("Press C to continue or Q to exit")
    choice = input().lower()
    if choice == "c":
        menu()
    elif choice == "q":
        exit()




def create_auth():

    os.system('clear')
    print (bcolors.Yellow + "***********   Create Authorization Key   ***************" + bcolors.ENDC)
    print ("What would you like for an object ID (0 = auto creates):")
    object_id = int(input())
    print ("What domains should this be assigned to:")
    domains = int(input())
    print ("What label would you like to set:")
    label = input()
    password = getpass.getpass()

    capabilities = CAPABILITY.ALL
    delegated_capabilities = CAPABILITY.ALL
    
    try:
        session = objHSM['session']
        key = AuthenticationKey.put_derived(session, object_id, label, domains, capabilities, delegated_capabilities, password)
    except yubihsm.exceptions.YubiHsmDeviceError:
        message = bcolors.Red + " Ojbect already exists " + bcolors.ENDC
        menu(message)


    print("Created new Auth key")
    print("Name: " + label)
    print("ID: " + str(key.id))
    print("")
    print("Press C to continue or Q to exit")
    choice = input().lower()
    if choice == "c":
        menu()
    elif choice == "q":
        exit()



def login(message=''):
    '''
    Gather login information from user
    '''

    os.system('clear')
    print (message)
    print ("YubiHSM Connector IP: ")
    serverip = input().lower()
    print ("Port number:")
    port = input().lower()
    print ("User ID #:")
    authid = int(input())
    password = getpass.getpass()

    connected = _session(authid, serverip, port, password)

    if(connected):
        menu()
    else:
        message = bcolors.Red + "Failed to connect. Please login again" + bcolors.ENDC
        login(message)
    
    return

def menu(message=''):

    os.system('clear')
    print (message)
    print ("1 - Device info")
    print ("2 - Create Auth Key")
    print ("3 - Create signing cert")
    print ("4 - List Objects")
    print ("10 - Reset device")
    print("")
    print("Press C to continue or Q to exit")

    choice = input().lower()
    if choice == "1":
        deviceinfo()
    elif choice == "2":
        create_auth()
    elif choice == "3":
        create_asymm()
    elif choice == "4":
        list_objects()
    elif choice == "10":
        reset_hardware()
    elif choice == 'q':
        exit()


def yubihsmloop(message=''):
    os.system('clear')
    print (message)
    print (bcolors.Blue + "********** YubiHSM Manager ****************" + bcolors.ENDC)
    print ("1 - Login")
    print ("2 - Set configuration file path")
    choice = input().lower()
    if choice == "1":
        login()
        yubihsmloop()
    elif choice == "2":
        set_config_path()
        yubihsmloop()
    elif choice == "q":
        exit()
    else:
        yubihsmloop(bcolors.Red + "That's an invalid option. Please select a valid option" + bcolors.ENDC)

if __name__ == '__main__':
    print (bcolors.Red + "******************* Warning ***************" + bcolors.ENDC)
    print ("This is not production ready code")
    print ("It should only be used to learn how to interface")
    print ("with the YubiHSM")
    print ("Do you want to continue?")
    print (bcolors.Yellow + "yes / NO" + bcolors.ENDC)
    choice = input().lower()
    if choice == 'yes':
        yubihsmloop()
