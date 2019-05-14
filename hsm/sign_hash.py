    
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

from yubihsm import YubiHsm
from yubihsm.objects import AsymmetricKey, YhsmObject
from yubihsm.defs import ALGORITHM, CAPABILITY, OBJECT

# IP Address and port of host for YubiHSM2 connector
serverip = "192.168.1.10"
port = "12345"

#Key ID and password for auth key to use
keyid = 99
password = "YubiHSMTestPassword"

hsm = YubiHsm.connect("http://{0}:{1}/connector/api".format(serverip, port))
session = hsm.create_session_derived(keyid, password)


# AsymmetricKey ID
signer_id = 100

key = AsymmetricKey(session, signer_id, OBJECT.ASYMMETRIC_KEY)

data = b"This is a test"

signature = key.sign_ecdsa(data)

print("Data Signed: " + str(data))
print("Signature: " + str(signature))

session.close()
hsm.close()
