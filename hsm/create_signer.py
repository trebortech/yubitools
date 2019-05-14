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
from yubihsm.objects import AsymmetricKey
from yubihsm.defs import ALGORITHM, CAPABILITY

# IP Address and port of host for YubiHSM2 connector
serverip = "192.168.1.10"
port = "12345"

#Key ID and password for auth key to use
keyid = 99  
password = "YubiHSMTestPassword"

hsm = YubiHsm.connect("http://{0}:{1}/connector/api".format(serverip, port))
session = hsm.create_session_derived(keyid, password)

'''
session
object_id
label
domains
capabilities
algorithm
'''

object_id = 100
label = "MyCodeSigner"
domains = 1
capabilities = CAPABILITY.SIGN_ECDSA
algorithm = ALGORITHM.EC_P256

key = AsymmetricKey.generate(session, object_id, label, domains, capabilities, algorithm)

print("Created new Auth key")
print("Name: " + label)
print("ID: " + str(key.id))
