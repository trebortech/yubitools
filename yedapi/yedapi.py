#!/usr/bin/env python3

'''
##############################
#
# NOT FOR PRODUCTION USE
#
# REFERENCE CODE ONLY
#
# USE AT YOUR OWN RISK!!!!
#
##############################
'''
#Remove this line if you read and understand the message above


# Import core libs
import json, os, requests, getpass, pprint

# Global Variables
objHSM = {}
currconnection = {}
defaultconfig = {
    "apikey": "hsm",
    "serverip": "127.0.0.1",
    "port": "12345",
    "authid": 1,
    "apiobjectid": 2
}
usehsm = True


# Import Yubico libs
# If HSM is selected for storage

try:
    import yubihsm.exceptions
    from yubihsm import YubiHsm
    from yubihsm.objects import Opaque

except ImportError:
    print (("*")*10)
    print ("To use the YubiHSM for secret storage you must have python-yubihsm installed")
    usehsm = False


def _session(
            authid=1,
            serverip="127.0.0.1",
            port="12345",
            password="password"):

    global objHSM
    try:
        hsm = YubiHsm.connect(f"http://{serverip}:{port}/api")
        session = hsm.create_session_derived(authid, password)
    except yubihsm.exceptions.YubiHsmAuthenticationError:
        message = "Login failed"
        return (False, message)
    except yubihsm.exceptions.YubiHsmConnectionError:
        message = "No route to host"
        return (False, message)
    except yubihsm.exceptions.YubiHsmDeviceError:
        message = "Login failed 2"
        return (False, message)
    except yubihsm.exceptions.YubiHsmInvalidResponseError:
        message = "Response error"
        return (False, message)

    objHSM = {"hsm": hsm, "session": session}
    message = "Successful Login"
    return (True, message)


def _config_import(configfile="yedapi.json"):
    global config
    if not(os.path.isfile(configfile)):
        # If the config file does not exist, create one with default settings.
        with open(configfile, "w") as fp:
            json.dump(defaultconfig, fp)
    config = json.load(open(configfile))
    # If apikey is set to HSM ask for password
    if config['apikey'] == 'hsm':
        if usehsm:
            password = getpass.getpass("What is the password for the YubiHSM key?")

            authid = config['authid']
            serverip = config['serverip']
            port = config['port']

            # Make connection to YubiHSM
            connected = _session(authid,serverip,port,password)

            if(connected[0]):
                # Good login move to Create key
                return "Good login"
            else:
                # Failure in login process. Try again.
                print("Error in login process")
                print(connected[1])
                exit()
        else:
            print("You need to have python-yubihsm installed")
            exit()
    return

def _call_api(resource=""):
    apikey = _get_api_key()

    auth_header = f'Bearer { apikey }'
    token1 = config['dev']['GCP_IAAP_AUTH_TOKEN']
    token2 = config['dev']['GCP_IAP_UID']
    cookie = f'GCP_IAAP_AUTH_TOKEN_9C3013A3C4153CC4={ token1 };GCP_IAP_UID={ token2 }'

    headers = {'Authorization': auth_header, 'cookie': cookie, 'Content-Type': 'application/json'}
    if config['dev']['url']:
        request_url = config['dev']['url']
    else:
        request_url = "https://api.console.yubico.com/v1"

    request_url += "/" + resource

    #import pdb;pdb.set_trace()
    r = requests.get(request_url, headers=headers)

    return r

def _get_api_key():
    # If HSM read object type
    if objHSM:
        hsmsession = objHSM['session']
        apikeyid = config['apiobjectid']
        opaquekey = Opaque(hsmsession, apikeyid)
        apikey = opaquekey.get().decode()

    else:
        apikey = config['apikey']
    return apikey

#def list_inventory():


#def shipment_status():


def list_products():
    resp = _call_api("products")
    pp = pprint.PrettyPrinter(indent=4)
    pp.pprint(resp.text)
    input("Press Enter to continue...")
    yedapiloop()

def yedapiloop(message=''):
    os.system('cls' if os.name == 'nt' else 'clear')
    print(message)
    print(("*") * 10)
    print("YED API Demo Tool")
    print(("*") * 10)
    print("1 - List Inventory ")
    print("2 - Shipment Status ")
    print("3 - List Products ")
    print(("*") * 5)
    choice = input().lower()
    if choice == "1":
        ...
    elif choice == "2":
        ...
    elif choice == "3":
        list_products()
    elif choice == "q":
        exit()
    else:
        yedapiloop("Invalid option. Please select from list")


if __name__ == '__main__':
    print(("*") * 10)
    print(" This tool is used as a demo for YEDAPI access ")
    print(("*") * 10)
    print("Do you want to continue? Y/N")
    choice = input().lower()
    if choice == 'y':
        _config_import("yedapi2.json")
        yedapiloop()