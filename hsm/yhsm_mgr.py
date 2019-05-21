#!/usr/bin/env python3

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


Coming features
- Banner that provides information on YubiHSM connected to
- Support for json configuration file
--- DONE - YubiHSM available connections
--- DONE - Capability grouping with alias
- Hashing of file 
- Verify hash of file
- Opaque object storage
- PRNG value
- Upload Asymmetric key
- Backup HSM
- Restore HSM
- Demo script setup (start with device reset)
- wrap data and store m of n keys on YubiKey static password
------ static password on yubikey is max 38 characters
------ wrap is larger than that and will need to be split. Slot 1 and Slot 2

'''

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


# Library imports
import json
import os
import sys
import os.path
import getpass
import random
import string

from hashlib import sha256

# Check if windows and import colorama is Windows

if os.name == 'nt':
    sys.path.append("c:\\program files (x86)\\Yubico\\YubiKey Manager")

try:
    from colorama import init
    init()
except ImportError:
    # If Windows
    if os.name == 'nt':
        print("Must install colorama on Windows")
        print("py.exe -m pip install colorama")
        exit()
    pass

# Import Yubico Libs
try:
    import yubihsm.exceptions

    from yubihsm import YubiHsm
    from yubihsm.objects import AuthenticationKey, AsymmetricKey, HmacKey
    from yubihsm.defs import CAPABILITY, ALGORITHM, OBJECT

    #from ykman import driver_ccid as CCID


except ImportError:
    print (("*"*10) + "   This script requires the python-yubihsm library to be installed    " + ("*"*10))
    print (("*"*10) + "   It also requires Python 3    " + ("*"*10))
    exit()


# Global variables
objHSM = {}
currconnection = {}
working_dir = ""

#Default config settings
defaultconfig = {
    "hsms": {
    },
    "cap_alias": {
        "sign ECDSA": 128,
        "root auth": 140737488355327                     
    }
}

def _randstring(str_size=5):
    allowed_chars = string.ascii_letters + string.punctuation
    return ''.join(random.choice(allowed_chars) for x in range(str_size))

def _session(authid=1, serverip="127.0.0.1", port="12345", password="password"):
    '''
    Create an authenticated session to the YubiHSM connector
    '''
    global objHSM

    try:
        hsm = YubiHsm.connect(f"http://{serverip}:{port}/connector/api")
        session = hsm.create_session_derived(authid, password)
    except yubihsm.exceptions.YubiHsmAuthenticationError:
        message = bcolors.Red + "Login failed" + bcolors.ENDC
        login(message)
    except yubihsm.exceptions.YubiHsmConnectionError:
        message = bcolors.Red + "No route to host" + bcolors.ENDC
        login(message)
    except yubihsm.exceptions.YubiHsmDeviceError:
        message = bcolors.Red + "Login failed 2" + bcolors.ENDC
        login(message)

    objHSM = {"hsm": hsm, "session": session}
    return True

def reset_hardware():
    '''
    Reset the YubiHSM to factory defaults
    '''
    global objHSM
    status_message()

    print(bcolors.Red + ("*"*40) + bcolors.ENDC)
    print(bcolors.Red + ("**") + bcolors.ENDC + " YOU ARE ABOUT TO RESET THE YUBIHSM ")
    print(bcolors.Red + ("**") + bcolors.ENDC + " ARE YOU SURE YOU WANT TO DO THIS? Y/N ")
    print(bcolors.Red + ("*"*40) + bcolors.ENDC)
    choice = input().lower()

    if choice == "y":
        passcode = _randstring()

        print(bcolors.Red + ("*"*40) + bcolors.ENDC)
        print(bcolors.Red + ("**") + bcolors.ENDC + " ARE YOU SURE? ")
        print(bcolors.Red + ("**") + bcolors.ENDC + " Type the following code if you want to continue: " + passcode)
        print(bcolors.Red + ("*"*40) + bcolors.ENDC)
        choice2 = input()

        if choice2 != passcode:
            menu(" Passcode was incorrect ")
            return False
        else:
            pass
    else:
        menu(" Device not reset")
        return False

    try:
        session = objHSM['session']
        session.reset_device()
        message = bcolors.Green + " Device has been reset. You must login again."
        objHSM = {}
        currconnection = {}
        yubihsmloop()
    except yubihsm.exceptions.YubiHsmInvalidResponseError:
        message = bcolors.Red + " Incorrect MAC " + bcolors.ENDC
        menu(message)
    return True

def status_message():
    '''
    Provide connection information
    '''
    os.system('cls' if os.name == 'nt' else 'clear')
    print(bcolors.Green + ("*"*40) + bcolors.ENDC)
    print(bcolors.Green + ("*"*5) + bcolors.ENDC)
    if len(currconnection):
        print(bcolors.Green + ("*"*5) + bcolors.ENDC + "  Connected YubiHSM:" +  currconnection['connector']['serverip'])
        print(bcolors.Green + ("*"*5) + bcolors.ENDC + "  User ID: " + str(currconnection['connector']['authid']))
    else:
        print(bcolors.Green + ("*"*5) + bcolors.ENDC + "  Connected YubiHSM:")
        print(bcolors.Green + ("*"*5) + bcolors.ENDC + "  User ID: ")
    
    print(bcolors.Green + ("*"*5) + bcolors.ENDC + "  Current Working Directory: " + working_dir)
    print(bcolors.Green + ("*"*5) + bcolors.ENDC)
    print(bcolors.Green + ("*"*40) + bcolors.ENDC)

    return 

    
def list_objects():
    '''
    List all the objects for a domain
    '''
    status_message()
    session = objHSM['session']

    objslist = session.list_objects()

    for objlist in objslist:
        obj = objlist.get_info()

        print (bcolors.Green + "ID: " + bcolors.ENDC + str(obj.id))
        print (bcolors.Green + "Label: " + bcolors.ENDC + obj.label )
        print (bcolors.Green + "Domains: " + bcolors.ENDC + str(obj.domains))
        print (bcolors.Green + "Type: " + bcolors.ENDC +  str(obj.object_type))
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
    status_message()
    hsm = objHSM['hsm']
    serialnumber = hsm.get_device_info().serial
    version = hsm.get_device_info().version
    print("")
    print("Device Information")
    print(bcolors.Green + "Serial number:" + bcolors.ENDC + str(serialnumber))
    print(bcolors.Green + "YubiHSM Version:" + bcolors.ENDC + str(version))
    print("")
    print("Press C to continue or Q to exit")
    choice = input().lower()
    if choice == "c":
        menu()
    elif choice == "q":
        exit()

def sign_data_hmac():
    status_message()
    print (bcolors.Green + "***********   Sign Data  ***************" + bcolors.ENDC)
    # List available key
    session = objHSM['session']

    try:
        objType = OBJECT.HMAC_KEY
        objslist = session.list_objects(object_type=objType)
        if len(objslist) == 0:
            menu("You must first create an HMAC key")
        for objlist in objslist:
            obj = objlist.get_info()
            print (str(obj.id) + " - " + obj.label)

        keyid = input("What key ID would you like to use:")
        datafilename = input("What is the name of the file you want to sign (current directory only):")

        '''
        datafile = open(datafilename).read()
        datafile = bytes(datafile, 'utf-8')
        digest = sha256(datafile).digest()[:16]
        hmackey = HmacKey(session, keyid)
        '''
        keyid = int(keyid)
        hmackey = HmacKey(session, keyid)
        datafile = open(datafilename, 'rb').read()
        signature = hmackey.sign_hmac(datafile)
        dataout = open(datafilename + "-" + str(keyid) +".sig", "+w")
        dataout.write(signature.hex())
        dataout.close()
        menu("File has been created with signature in it for " + datafilename)
    except yubihsm.exceptions.YubiHsmDeviceError:
        menu("Failed signing")
    menu()
    return

def create_hmac():
    status_message()
    print (bcolors.Green + "***********   Create HMAC Key  ***************" + bcolors.ENDC)
    print ("What would you like for an object ID (0 = auto creates):")
    object_id = int(input())
    print ("What domains should this be assigned to:")
    domains = int(input())
    print ("What label would you like to set:")
    # TODO: Needs to be no longer than 40 bytes
    label = input()

    # sign hmac + verify hmac
    capabilities = 12582912
    algorithm = ALGORITHM.HMAC_SHA256

    try:
        session = objHSM['session']
        key = HmacKey.generate(session, object_id, label, domains, capabilities, algorithm)
    except yubihsm.exceptions.YubiHsmDeviceError:
        print("Error")

    
    print("Created new HMAC key")
    print("Name: " + label)
    print("ID: " + str(key.id))
    print("Press C to continue or Q to exit")
    choice = input().lower()
    if choice == "c":
        menu()
    elif choice == "q":
        exit()

def create_asymm():
    #TODO: Support multiple domains
    #TODO: Trim lable to 40 bytes

    status_message()
    print (bcolors.Green + "***********   Create Asymmetric Key Pair for signing operations  ***************" + bcolors.ENDC)
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

    status_message()
    print (bcolors.Green + "***********   Create Authorization Key   ***************" + bcolors.ENDC)
    object_id = int(input("What would you like for an object ID (0 = auto creates):   "))
    domains = input("What domains should this be assigned to:  ")
    label = input("What label would you like to set:  ")
    password = getpass.getpass("What password would you like to set (will not echo to screen):  ")

    domainslist = domains.split(",")
    set(domainslist)

    print ("Available Capability settings")
    itemnum = 1
    itemlist = {}
    for cap in config['cap_alias']:
        print(str(itemnum) + " - " + cap)
        itemlist[itemnum] = cap
        itemnum += 1
    selcap = input("Which capability set would you like to use:  ")

    selconfig = itemlist[int(selcap)]

    capabilities = config['cap_alias'][selconfig]
    delegated_capabilities = config['cap_alias'][selconfig] 
    
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

def login(message='', configname='', *args, **kwargs):
    '''
    Gather login information from user
    '''
    os.system('cls' if os.name == 'nt' else 'clear')

    if configname:
        serverip = config['hsms'][configname]['serverip'] 
        port = config['hsms'][configname]['port']
        authid = int(config['hsms'][configname]['authid'])

        print(f"Connection to http://{serverip}:{port} using auth id {authid}")
    else:    
        print (message)
        print ("YubiHSM Connector IP: ")
        serverip = input().lower()
        print ("Port number:")
        port = input().lower()
        print ("User ID #:")
        authid = int(input())
    
    password = getpass.getpass("Password to auth id (will not echo to screen):")

    currconnection['connector'] = {"serverip": serverip, "port": port, "authid": authid}

    connected = _session(authid, serverip, port, password)

    if(connected):
        menu()
    else:
        message = bcolors.Red + "Failed to connect. Please login again" + bcolors.ENDC
        login(message)
    
    return


'''
Menu Section

'''

def config_import(configfile="yhsm_mgr.json"):
    global config
    global working_dir
    
    if len(working_dir) == 0:
        working_dir = os.getcwd()

    if not(os.path.isfile(configfile)):
        with open(configfile, "w") as fp:
            json.dump(defaultconfig, fp)
    config = json.load(open(configfile))
    return 

def menu(message=''):
    status_message()
    print (message)
    print ("1 - Device info")
    print ("2 - List Objects")
    print ("3 - Get Random Number")
    print ("4 - Create Auth Key")
    print ("5 - Create Asymmetric key")
    print ("6 - Create HMAC Key")
    print ("7 - Sign with HMAC")
    print ("99 - Reset device")
    print("")
    print("Press C to continue or Q to exit")

    choice = input().lower()
    if choice == "1":
        deviceinfo()
    elif choice == "2":
        list_objects()
    elif choice == "3":
        get_random()
    elif choice == "4":
        create_auth()
    elif choice == "5":
        create_asymm()
    elif choice == "6":
        create_hmac()
    elif choice == "7":
        sign_data_hmac()
    elif choice == "99":
        reset_hardware()
    elif choice == 'q':
        exit()

def set_config_path():
    global working_dir
    print (bcolors.Green + "********** Set working directory ****************" + bcolors.ENDC)
    working_dir = input("Change working directory to (must already exist):").strip()
    if (not os.path.isdir(working_dir)):
        print (bcolors.Red + "PATH DOES NOT EXIST" + bcolors.ENDC)
    else:
        os.chdir(working_dir)
    config_import()
    return

def yubihsmloop(message=''):
    config_import()
    status_message()
    print (message)
    print (bcolors.Green + "********** YubiHSM Manager ****************" + bcolors.ENDC)
    print ("1 - Login")
    print ("2 - Set configuration file path")

    itemnum = 3
    itemlist = {}
    for hsm in config['hsms']:
        print ( str(itemnum) + " - " + hsm)
        itemlist[itemnum] = hsm
        itemnum = itemnum + 1
    print ("")

    choice = input().lower()
    if choice == "1":
        login()
        yubihsmloop()
    elif choice == "2":
        set_config_path()
        yubihsmloop()
    elif int(choice) > 2:
        configname = itemlist[int(choice)]
        login(configname=configname)
    elif choice == "q":
        exit()
    else:
        yubihsmloop(bcolors.Red + "Invalid option. Please select an option from the list" + bcolors.ENDC)

if __name__ == '__main__':
    print (bcolors.Red + "******************* Warning ***************" + bcolors.ENDC)
    print ("This is not production ready code")
    print ("It should only be used to learn how to interface")
    print ("with the YubiHSM")
    print ("Do you want to continue?")
    print (bcolors.Green + "yes / NO" + bcolors.ENDC)
    choice = input().lower()
    if choice == 'yes':
        yubihsmloop()
