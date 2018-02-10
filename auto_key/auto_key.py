
# Import core libs
from binascii import a2b_hex
import json
import string
import random
import time
import usb.core
import os.path

# Import Yubico libs
from ykman import driver_ccid as CCID
from ykman import piv as PIV


# Method to configure yubikey using config

def config_key():

    defaultPIN = '123456'
    defaultPUK = '12345678'
    defaultMGT = '010203040506070801020304050607080102030405060708'
    byteMGT = a2b_hex(defaultMGT)
    
    if os.path.isfile('auto_key.json'):
        config = json.load(open('auto_key.json'))
    else:
        config = {}
        print "No configuration file is available. Using defaults"

    # Retries
    if 'pinretries' not in config:
        config['pinretries'] = 6
    if 'pukretries' not in config:
        config['pukretries'] = 6

    # PIN
    if 'defaultpin' not in config:
        config['defaultpin'] = "factory"
    if 'staticpin' not in config:
        config['staticpin'] = defaultPIN

    # PUK
    if 'defaultpuk' not in config:
        config['defaultpuk'] = "factory"
    if 'staticpuk' not in config:
        config['staticpuk'] = defaultPUK

    # Management Key
    if 'defaultmgt' not in config:
        config['defaultmgt'] = "factory"
    if 'staticmgt' not in config:
        config['staticmgt'] = defaultMGT


    # Device Dictionary
    yk = {}

    objCCIDDevices = CCID.open_devices()
    driverCCID = objCCIDDevices.next()
    controllerPIV = PIV.PivController(driverCCID)

    yk['serial'] = driverCCID.serial
    print "Working on key: {0}".format(yk['serial'])

    # Reset key to factory defaults
    controllerPIV.reset()

    # Authenticate to key
    controllerPIV.verify(defaultPIN)
    controllerPIV.authenticate(byteMGT)

    # Reset PIN Retries
    pintries = config['pinretries']
    puktries = config['pukretries']
    controllerPIV.set_pin_retries(pintries, puktries)

    # Update PIN
    if config['defaultpin'] == 'random':
        newPIN = str(random.randint(10000000, 99999999))
    elif config['defaultpin'] == 'serial':
        newPIN = yk['serial']
    elif config['defaultpin'] == 'static':
        newPIN = config['staticpin']
    elif config['defaultpin'] == 'factory':
        newPIN = config['staticpin']

    if newPIN != defaultPIN:
        newPIN = str(newPIN)
        print "New PIN: {0}".format(newPIN)
        controllerPIV.change_pin(defaultPIN, newPIN)
    else:
        print "PIN was not updated"

    # Update PUK
    if config['defaultpuk'] == 'random':
        newPUK = str(random.randint(10000000, 99999999))
    elif config['defaultpuk'] == 'serial':
        newPUK = yk['serial']
    elif config['defaultpuk'] == 'static':
        newPUK = config['staticpuk']
    elif config['defaultpuk'] == 'factory':
        newPUK = config['staticpuk']

    if newPUK != defaultPUK:
        newPUK = str(newPUK)
        print "New PUK: {0}".format(newPUK)
        controllerPIV.change_puk(defaultPUK, newPUK)
    else:
        print "PUK was not updated"

    # Update MGT Key
    if config['defaultmgt'] == 'random':
        newMGT = rnd_string(48, 'base16')
    elif config['defaultmgt'] == 'serial':
        newMGT = yk['serial']
    elif config['defaultmgt'] == 'static':
        newMGT = config['staticmgt']
    elif config['defaultmgt'] == 'factory':
        newMGT = config['staticmgt']

    if newMGT != defaultMGT:
        newMGT = str(newMGT)
        bytenewMGT = a2b_hex(newMGT)
        controllerPIV.set_mgm_key(bytenewMGT)
        print "New Management Key: {0}".format(newMGT)
    else:
        print "Management Key was not updated"
    return

def rnd_string(intLen=42, type='alpha_numeric'):
    if type == 'base16':
        ret = ''.join(random.SystemRandom().choice('0123456789abcdef') for _ in range(intLen))
    else:
        ret = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(intLen))
    return ret

# Running loop for USB insertion
def usbloop():
    keystatus = 'out'
    try:
        while True:
            dev = usb.core.find(find_all=True)
            ykdev = []
            for key in dev:
                if 'Yubikey' in key.product:
                    ykdev.append(key)
            if len(ykdev) == 0:
                keystatus = 'out'
                print "No Yubikey plugged in"
            elif len(ykdev) > 1:
                print "Please only have a single Yubikey plugged in at a time"
            elif len(ykdev) == 1 and keystatus == 'out':
                keystatus = 'in'
                print "Start Key Configuration"
                config_key()
                print "Completed Key Configuration"
                print "Please Remove key"
                print "Press Ctrl+c to exit"
            time.sleep(2)
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
	usbloop()
