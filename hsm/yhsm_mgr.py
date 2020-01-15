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
- DONE - Banner that provides information on YubiHSM connected to
- Support for json configuration file
--- DONE - YubiHSM available connections
--- DONE - Capability grouping with alias
- DONE - HMAC Hashing of file
- DONE - Create HMAC key
- Verify hash of file
- Opaque object storage
- DONE - PRNG value
- DONE - Upload Asymmetric key
- Backup HSM
- Restore HSM
- Demo script setup (start with device reset)
- wrap data and store m of n keys on YubiKey static password
------ static password on yubikey is max 38 characters
------ wrap is larger than that and will need to be split. Slot 1 and Slot 2
- Clean up PEP8

'''
# Library imports
import json
import os
import sys
import os.path
import getpass
import random
import string

from hashlib import sha256
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key

sdk_version = 2
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


except ImportError:
    print(("*"*10),
          "   This script requires the python-yubihsm library to be ",
          "installed    " + ("\*"*10))
    print(("*"*10) + "   It also requires Python 3    " + ("*"*10))
    exit()


# Global variables
objHSM = {}
currconnection = {}
working_dir = ""

# Default config settings
defaultconfig = {
    "hsm_configs": {
    },
    "alias_capabilities": {
        "sign ECDSA": 128,
        "root auth": 140737488355327
    }
}


def _hsmdomains(domains):
    domainslist = domains.split(",")
    set(domainslist)

    domains = {
        1: 1 << 0x00,
        2: 1 << 0x01,
        3: 1 << 0x02,
        4: 1 << 0x03,
        5: 1 << 0x04,
        6: 1 << 0x05,
        7: 1 << 0x06,
        8: 1 << 0x07,
        9: 1 << 0x08,
        10: 1 << 0x09,
        11: 1 << 0x0a,
        12: 1 << 0x0b,
        13: 1 << 0x0c,
        14: 1 << 0x0d,
        15: 1 << 0x0e,
        16: 1 << 0x0f
    }

    domaintotal = 0
    for i in domainslist:
        domaintotal = domaintotal + domains[int(i)]

    return domaintotal


def _hsmtodomains(domainint):
    bitstring = "{0:b}".format(domainint)
    retdomain = []
    position = len(bitstring)
    for i in bitstring:
        if int(i) == 1:
            retdomain.append(position)
        position -= 1

    return set(retdomain)


def _randstring(str_size=5):
    allowed_chars = string.ascii_letters + string.punctuation
    return ''.join(random.choice(allowed_chars) for x in range(str_size))


def _session(
            authid=1,
            serverip="127.0.0.1",
            port="12345",
            password="password"):
    '''
    Create an authenticated session to the YubiHSM connector
    '''
    global objHSM

    try:
        if sdk_version == 2:
            hsm = YubiHsm.connect(f"http://{serverip}:{port}/connector/api")
        else:
            hsm = YubiHsm.connect(f"http://{serverip}:{port}/connector/api")
        session = hsm.create_session_derived(authid, password)
    except yubihsm.exceptions.YubiHsmAuthenticationError:
        message = bcolors.Red + "Login failed" + bcolors.ENDC
        return (False, message)
    except yubihsm.exceptions.YubiHsmConnectionError:
        message = bcolors.Red + "No route to host" + bcolors.ENDC
        return (False, message)
    except yubihsm.exceptions.YubiHsmDeviceError:
        message = bcolors.Red + "Login failed 2" + bcolors.ENDC
        return (False, message)
    except yubihsm.exceptions.YubiHsmInvalidResponseError:
        message = bcolors.Red + "Response error" + bcolors.ENDC
        return (False, message)

    objHSM = {"hsm": hsm, "session": session}
    message = bcolors.Green + "Successful Login" + bcolors.ENDC
    return (True, message)


def _status_message():
    '''
    Provide connection information
    '''
    os.system('cls' if os.name == 'nt' else 'clear')
    print(bcolors.Green + ("*"*40) + bcolors.ENDC)
    print(bcolors.Green + ("*"*5) + bcolors.ENDC)
    if len(currconnection):
        print(bcolors.Green + ("*"*5) + bcolors.ENDC + "  Connected YubiHSM:",
              currconnection['connector']['serverip'])
        print(bcolors.Green + ("*"*5) + bcolors.ENDC + "  Auth ID: ",
              str(currconnection['connector']['authid']))
    else:
        print(bcolors.Green + ("*"*5) + bcolors.ENDC + "  Connected YubiHSM:")
        print(bcolors.Green + ("*"*5) + bcolors.ENDC + "  Auth ID: ")

    print(bcolors.Green + ("*"*5) + bcolors.ENDC + "  Current Working ",
          "Directory: " + working_dir)
    print(bcolors.Green + ("*"*5) + bcolors.ENDC)
    print(bcolors.Green + ("*"*40) + bcolors.ENDC)

    return


def _login(message='', configname='', *args, **kwargs):
    '''
    Gather login information from user
    '''
    os.system('cls' if os.name == 'nt' else 'clear')

    print(message)
    if configname:
        # Use information from configuration file
        serverip = config['hsm_configs'][configname]['serverip']
        port = config['hsm_configs'][configname]['port']
        authid = int(config['hsm_configs'][configname]['authid'])

        print(f"Connection to http://{serverip}:{port} using auth id {authid}")
    else:
        # User needs to provide all the information for login
        print("YubiHSM Connector IP: ")
        serverip = input().lower()
        print("Port number:")
        port = input().lower()
        print("User ID #:")
        authid = int(input())

    password = getpass.getpass(
        "Password to auth id (will not echo to screen) or c to cancel:")

    currconnection['connector'] = {
        "serverip": serverip,
        "port": port,
        "authid": authid}

    if password.lower() == 'c':
        yubihsmloop("Cancel login")

    connected = _session(authid, serverip, port, password)
    if(connected[0]):
        menu(connected[1])
    else:
        _login(connected[1], configname)
    return


def _config_import(configfile="yhsm_mgr.json"):
    global config
    global working_dir

    if len(working_dir) == 0:
        working_dir = os.getcwd()

    if not(os.path.isfile(configfile)):
        with open(configfile, "w") as fp:
            json.dump(defaultconfig, fp)
    config = json.load(open(configfile))
    return


def _set_config_path():
    global working_dir
    print(bcolors.Green,
          "********** Set working directory ****************" + bcolors.ENDC)
    working_dir = input(
        "Change working directory to (must already exist):").strip()

    if working_dir[:1] == "+":
        working_dir = os.getcwd() + working_dir[1:]

    if (not os.path.isdir(working_dir)):
        print(bcolors.Red + "PATH DOES NOT EXIST" + bcolors.ENDC)
    else:
        os.chdir(working_dir)
    _config_import()
    return

# ******************************************************************************
# ***              DEVICE SECTION
# ******************************************************************************


def reset_hardware():
    '''
    Reset the YubiHSM to factory defaults
    '''
    global objHSM
    _status_message()

    print(bcolors.Red + ("*"*40) + bcolors.ENDC)
    print(bcolors.Red + ("**") + bcolors.ENDC,
          " YOU ARE ABOUT TO RESET THE YUBIHSM ")
    print(bcolors.Red + ("**") + bcolors.ENDC,
          " ARE YOU SURE YOU WANT TO DO THIS? Y/N ")
    print(bcolors.Red + ("*"*40) + bcolors.ENDC)
    choice = input().lower()

    if choice == "y":
        passcode = _randstring()

        print(bcolors.Red + ("*"*40) + bcolors.ENDC)
        print(bcolors.Red + ("**") + bcolors.ENDC,
              " ARE YOU SURE? ")
        print(bcolors.Red + ("**") + bcolors.ENDC,
              " Type the following code if you want to continue: " + passcode)
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
        message = bcolors.Green,
        " Device has been reset. You must login again.",
        bcolors.ENDC
        objHSM = {}
        currconnection = {}
        yubihsmloop()
    except yubihsm.exceptions.YubiHsmInvalidResponseError:
        message = bcolors.Red + " Incorrect MAC " + bcolors.ENDC
        menu(message)
    return True


def list_objects():
    '''
    List all the objects for a domain
    '''
    _status_message()
    session = objHSM['session']

    try:
        objslist = session.list_objects()

        for objlist in objslist:
            obj = objlist.get_info()

            print(bcolors.Green + "ID: " + bcolors.ENDC + str(obj.id))
            print(bcolors.Green + "Label: " + bcolors.ENDC + obj.label)
            print(bcolors.Green + "Domains: " + bcolors.ENDC,
                  str(_hsmtodomains(obj.domains)))
            print(bcolors.Green + "Type: " + bcolors.ENDC,
                  str(obj.object_type))
            print("----------------------------")

        print("Press C to continue or Q to exit")
        choice = input().lower()
        if choice == "c":
            menu()
        elif choice == "q":
            exit()
    except yubihsm.exceptions.YubiHsmInvalidResponseError:
        message = bcolors.Red + " Incorrect MAC " + bcolors.ENDC
        menu(message)


def deviceinfo():
    '''
    Get the device information
    '''
    _status_message()
    hsm = objHSM['hsm']
    try:
        serialnumber = hsm.get_device_info().serial
        version = hsm.get_device_info().version
        print("")
        print("Device Information")
        print(bcolors.Green + "Serial number:" + bcolors.ENDC,
              str(serialnumber))
        print(bcolors.Green + "YubiHSM Version:" + bcolors.ENDC + str(version))
        print("")
        choice = input("Press C to continue or Q to exit").lower()
        if choice == "c":
            menu()
        elif choice == "q":
            exit()
    except yubihsm.exceptions.YubiHsmInvalidResponseError:
        message = bcolors.Red + " Incorrect MAC " + bcolors.ENDC
        menu(message)


def get_random():
    '''
    Get a random number
    '''

    _status_message()
    try:
        print("Pseudo random number generator")
        intlen = input("Number of bytes requested:")
        session = objHSM['session']
        prngr = session.get_pseudo_random(int(intlen))

        print("")
        print(bcolors.Green,
              "Generatred number:" + bcolors.ENDC + prngr.hex())
        print("")
        choice = input("Press C to continue or Q to exit").lower()
        if choice == "c":
            menu()
        elif choice == "q":
            exit()
    except yubihsm.exceptions.YubiHsmInvalidResponseError:
        message = bcolors.Red + " Incorrect MAC " + bcolors.ENDC
        menu(message)

# ******************************************************************************
# ***              SIGN SECTION
# ******************************************************************************


def sign_data(keytype='hmac256'):
    _status_message()
    print(bcolors.Green,
          "***********   Sign Data  ***************" + bcolors.ENDC)
    # List available key
    session = objHSM['session']

    keytypes = {
        "hmac256": {
                "name": "HMAC",
                "type": "hmac",
                "filename": "hmac256",
                "cap": config['capabilities']['sign hmac'],
                "algo": config['algorithm']['hmac sha256'],
                "objType": OBJECT.HMAC_KEY},
        "asymm_ecdsa_p256": {
                "name": "Asymmetric",
                "type": "ecdsa",
                "filename": "ecdsa-p256",
                "cap": config['capabilities']["sign ecdsa"],
                "algo": config['algorithm']["ec p256"],
                "objType": OBJECT.ASYMMETRIC_KEY},
        "asymm_pkcs1": {
                "name": "Asymmetric",
                "type": "pkcs1",
                "filename": "pkcs1-",
                "cap": config['capabilities']["sign ecdsa"],
                "algo": config['algorithm']["ec p256"],
                "objType": OBJECT.ASYMMETRIC_KEY}
    }

    try:
        objType = keytypes[keytype]['objType']
        cap = keytypes[keytype]['cap']
        algo = keytypes[keytype]['algo']

        objslist = session.list_objects(
            object_type=objType,
            capabilities=cap,
            algorithm=algo)
        if len(objslist) == 0:
            menu(f"You must first create an {keytypes[keytype]['name']} key")
        for objlist in objslist:
            obj = objlist.get_info()
            print(str(obj.id) + " - " + obj.label)

        keyid = input("What key ID would you like to use:")
        datafilename = input(
            "What is the name of the file you want to sign "
            "(current directory only):")

        keyid = int(keyid)
        sha256hash = sha256()
        with open(datafilename, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256hash.update(byte_block)

        dataout = open("signature_file-" + str(keyid) + ".sig", "a+")

        objCategory = keytypes[keytype]['type']
        if objCategory == 'hmac':
            hmackey = HmacKey(session, keyid)
            signature = hmackey.sign_hmac(sha256hash.digest())
        elif objCategory == "ecdsa":
            asymmkey = AsymmetricKey(session, keyid)
            signature = asymmkey.sign_ecdsa(sha256hash.digest())
        elif objCategory == "pkcs1":
            asymmkey = AsymmetricKey(session, keyid)
            signature = asymmkey.sign_pkcs1v1_5(sha256hash.digest())

        dataout.write(f"{datafilename}-sha256-{keytypes[keytype]['filename']}-{signature.hex()}\n")
        dataout.close()
        menu("File has been created with signature in it for " + datafilename)
    except yubihsm.exceptions.YubiHsmInvalidResponseError:
        message = bcolors.Red + " Incorrect MAC " + bcolors.ENDC
        menu(message)
    except yubihsm.exceptions.YubiHsmConnectionError:
        message = bcolors.Red + " Connection ERROR " + bcolors.ENDC
        menu(message)
    menu()
    return


def sign_pkcs1():
    _status_message()
    print(bcolors.Green,
          "***********   Sign Data PKCS1 ***************" + bcolors.ENDC)
    # List available key
    session = objHSM['session']

    try:
        objType = OBJECT.ASYMMETRIC_KEY
        objslist = session.list_objects(object_type=objType)
        if len(objslist) == 0:
            menu("You must first create Asymmetric key")
        for objlist in objslist:
            obj = objlist.get_info()
            print(str(obj.id) + " - " + obj.label)

        keyid = input("What key ID would you like to use:")
        datafilename = input(
            "What is the name of the file you want to sign "
            "(current directory only):")

        keyid = int(keyid)
        asymmkey = AsymmetricKey(session, keyid)

        sha256hash = sha256()
        with open(datafilename, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256hash.update(byte_block)

        signature = asymmkey.sign_pkcs1v1_5(sha256hash.digest())
        dataout = open("signature_file-" + str(keyid) + ".sig", "a+")
        dataout.write(datafilename + "-sha256-pkcs1-" + signature.hex() + "\n")
        dataout.close()
        menu("File has been created with signature in it for " + datafilename)
    except yubihsm.exceptions.YubiHsmInvalidResponseError:
        message = bcolors.Red + " Incorrect MAC " + bcolors.ENDC
        menu(message)
    except yubihsm.exceptions.YubiHsmConnectionError:
        message = bcolors.Red + " Connection ERROR " + bcolors.ENDC
        menu(message)
    except yubihsm.exceptions.YubiHsmDeviceError:
        message = bcolors.Red + " Invalid Data " + bcolors.ENDC
        menu(message)
    menu()
    return


def sign_eddsa():
    _status_message()
    print(bcolors.Green,
          "***********   Sign Data  ***************" + bcolors.ENDC)
    # List available key
    session = objHSM['session']

    try:
        objType = OBJECT.ASYMMETRIC_KEY
        objslist = session.list_objects(object_type=objType)
        if len(objslist) == 0:
            menu("You must first create Asymmetric key")
        for objlist in objslist:
            obj = objlist.get_info()
            print(str(obj.id) + " - " + obj.label)

        keyid = input("What key ID would you like to use:")
        datafilename = input(
            "What is the name of the file you want to sign "
            "(current directory only):")

        keyid = int(keyid)
        asymmkey = AsymmetricKey(session, keyid)

        sha256hash = sha256()
        with open(datafilename, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256hash.update(byte_block)

        signature = asymmkey.sign_eddsa(sha256hash.digest())
        dataout = open("signature_file-" + str(keyid) + ".sig", "a+")
        dataout.write(datafilename + "-sha256-ecdsa-" + signature.hex() + "\n")
        dataout.close()
        menu("File has been created with signature in it for " + datafilename)
    except yubihsm.exceptions.YubiHsmInvalidResponseError:
        message = bcolors.Red + " Incorrect MAC " + bcolors.ENDC
        menu(message)
    except yubihsm.exceptions.YubiHsmConnectionError:
        message = bcolors.Red + " Connection ERROR " + bcolors.ENDC
        menu(message)
    except yubihsm.exceptions.YubiHsmDeviceError:
        message = bcolors.Red + " Invalid Data " + bcolors.ENDC
        menu(message)
    menu()
    return

# ******************************************************************************
# ***              CREATE SECTION
# ***
# ******************************************************************************


def create_auth():

    _status_message()
    print(bcolors.Green + "***********   Create Authorization Key   ",
          "***************" + bcolors.ENDC)
    object_id = int(input("What would you like for an object ID (0 = "
                          "auto creates):   "))
    domains = input("What domains should this be assigned to:  ")
    label = input("What label would you like to set:  ")[:19]
    password = getpass.getpass("What password would you like to set ",
                               "(will not echo to screen):  ")

    domainint = _hsmdomains(domains)

    print("Available Capability settings")
    itemnum = 1
    itemlist = {}
    for cap in config['alias_capabilities']:
        print(str(itemnum) + " - " + cap)
        itemlist[itemnum] = cap
        itemnum += 1
    selcap = input("Which capability set would you like to use:  ")

    selconfig = itemlist[int(selcap)]

    capabilities = config['alias_capabilities'][selconfig]
    delegated_capabilities = config['alias_capabilities'][selconfig]

    try:
        session = objHSM['session']
        key = AuthenticationKey.put_derived(
            session,
            object_id,
            label,
            domainint,
            capabilities,
            delegated_capabilities,
            password)

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
    except yubihsm.exceptions.YubiHsmDeviceError:
        print("Error")
    except yubihsm.exceptions.YubiHsmInvalidResponseError:
        message = bcolors.Red + " Incorrect MAC " + bcolors.ENDC
        menu(message)


def create_key(keytype="hmac"):

    _status_message()
    # Key type settings
    keytypes = {
        "asymm": {
            "name": "Asymmetric"},
        "hmac": {
            "name": "HMAC"}
    }

    print(bcolors.Green,
          f"***********   Create {keytypes[keytype]['name']} Key   ",
          "***************" + bcolors.ENDC)
    object_id = int(input("What would you like for an object ID (0 = "
                          "auto creates):   "))
    domains = input("What domains should this be assigned to:  ")
    label = input("What label would you like to set:  ")[:19]

    domainint = _hsmdomains(domains)

    print("Available Capability settings")
    itemnum = 1
    itemlist = {}
    for cap in config['alias_capabilities']:
        print(str(itemnum) + " - " + cap)
        itemlist[itemnum] = cap
        itemnum += 1
    selcap = input("Which capability set would you like to use:  ")
    selconfig = itemlist[int(selcap)]

    capabilities = config['alias_capabilities'][selconfig]
    # Available algorithm for keys
    print("Available Algorithm set settings")
    itemnum = 1
    itemlist = {}
    for cap in config['alias_algorithms']:
        print(str(itemnum) + " - " + cap)
        itemlist[itemnum] = cap
        itemnum += 1
    selcap = input("Which algorithm set would you like to use:  ")
    selconfig = itemlist[int(selcap)]

    selected_algorithm = config['alias_algorithms'][selconfig]

    try:
        session = objHSM['session']

        if keytype == 'asymm':
            key = AsymmetricKey.generate(
                session,
                object_id,
                label,
                domainint,
                capabilities,
                selected_algorithm)
        elif keytype == "hmac":
            key = HmacKey.generate(
                session,
                object_id,
                label,
                domainint,
                capabilities,
                selected_algorithm)

        print("Created new key")
        print("Name: " + label)
        print("ID: " + str(key.id))
        print("")
        print("Press C to continue or Q to exit")
        choice = input().lower()
        if choice == "c":
            menu()
        elif choice == "q":
            exit()
    except yubihsm.exceptions.YubiHsmDeviceError:
        print("Error")
    except yubihsm.exceptions.YubiHsmInvalidResponseError:
        message = bcolors.Red + " Incorrect MAC " + bcolors.ENDC
        menu(message)


# ******************************************************************************
# ***              IMPORT SECTION
# ******************************************************************************


def upload_asymm():

    _status_message()
    print(bcolors.Green + "***********   Import Asymmetric Private Key   ",
          "***************" + bcolors.ENDC)
    object_id = int(input("What would you like for an object ID (0 = auto "
                          "creates):   "))
    domains = input("What domains should this be assigned to:  ")
    label = input("What label would you like to set:  ")[:19]
    filename = input("What is the name of the file to import:")
    print("Available Capability settings")
    itemnum = 1
    itemlist = {}
    for cap in config['alias_capabilities']:
        print(str(itemnum) + " - " + cap)
        itemlist[itemnum] = cap
        itemnum += 1
    selcap = input("Which capability set would you like to use:  ")

    selconfig = itemlist[int(selcap)]

    capabilities = config['alias_capabilities'][selconfig]
    domainint = _hsmdomains(domains)

    pemfile = open(filename, 'rb')
    pemlines = pemfile.read()
    pemfile.close()

    privatekey = load_pem_private_key(pemlines, None, default_backend())

    try:
        session = objHSM['session']
        key = AsymmetricKey.put(
            session,
            object_id,
            label,
            domainint,
            capabilities,
            privatekey)
        print("Name: " + label)
        print("ID: " + str(key.id))
        print("")
        print("Press C to continue or Q to exit")
        choice = input().lower()
        if choice == "c":
            menu()
        elif choice == "q":
            exit()
    except yubihsm.exceptions.YubiHsmDeviceError:
        print("Error")
    except yubihsm.exceptions.YubiHsmInvalidResponseError:
        message = bcolors.Red + " Incorrect MAC " + bcolors.ENDC
        menu(message)


# ******************************************************************************
# ***              MENU SECTION
# ******************************************************************************


def menu(message=''):
    _status_message()
    print(message)
    print("1 - Device info")
    print("2 - List Objects")
    print("3 - Get Random Number")
    print("4 - Create Auth Key")
    print("5 - Create Asymmetric key")
    print("6 - Import Asymmetric key")
    print("7 - Sign PKCS1")
    print("8 - Sign ECDSA")
    print("9 - Sign EDDSA")
    print("10 - Create HMAC Key")
    print("11 - Sign with HMAC")
    print("")
    print("")
    print("RESET - Reset device")
    print("LOGOUT - Logout")
    print("")
    print("Press Q to exit")

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
        create_key("asymm")
    elif choice == "6":
        upload_asymm()
    elif choice == "7":
        sign_pkcs1()
    elif choice == "8":
        sign_data("asymm_ecdsa_p256")
    elif choice == "9":
        sign_eddsa()
    elif choice == "10":
        create_key("hmac")
    elif choice == "11":
        sign_data("hmac256")
    elif choice == "reset":
        reset_hardware()
    elif choice == "logout":
        yubihsmloop(message="Logged out")
    elif choice == 'q':
        exit()


def yubihsmloop(message=''):
    _config_import()
    _status_message()
    print(message)
    print(bcolors.Green,
          "********** YubiHSM Manager ****************" + bcolors.ENDC)
    print("1 - Login")
    print("2 - Set configuration file path")

    itemnum = 3
    itemlist = {}
    for hsm in config['hsm_configs']:
        print(str(itemnum) + " - " + hsm)
        itemlist[itemnum] = hsm
        itemnum = itemnum + 1
    print("")

    choice = input().lower()
    if choice == "1":
        _login()
        yubihsmloop()
    elif choice == "2":
        _set_config_path()
        yubihsmloop()
    elif int(choice) > 2:
        configname = itemlist[int(choice)]
        _login(configname=configname)
    elif choice == "q":
        exit()
    else:
        yubihsmloop(bcolors.Red + "Invalid option. Please select an ",
                    "option from the list" + bcolors.ENDC)

if __name__ == '__main__':
    print(bcolors.Red,
          "******************* Warning ***************" + bcolors.ENDC)
    print("This is not production ready code")
    print("It should only be used to learn how to interface")
    print("with the YubiHSM")
    print("Do you want to continue?")
    print(bcolors.Green + "yes / NO" + bcolors.ENDC)
    choice = input().lower()
    if choice == 'yes':
        yubihsmloop()
