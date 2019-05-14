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
from yubihsm.objects import AuthenticationKey
from yubihsm.defs import CAPABILITY

# IP Address and port of host for YubiHSM2 connector
serverip = "192.168.1.10"
port = "12345"

# Default password for reset YubiHSM2
# Note: This should be removed
password = "password"

hsm = YubiHsm.connect("http://{0}:{1}/connector/api".format(serverip, port))
session = hsm.create_session_derived(1, password)

'''
session
object_id
label
domains
capabilities
delegated_capabilities
password
'''

object_id = 99
label = "myTestAuth"
domains = 1
capabilities = CAPABILITY.ALL
delegated_capabilities = CAPABILITY.ALL
password = "YubiHSMTestPassword"

key = AuthenticationKey.put_derived(session, object_id, label, domains, capabilities, delegated_capabilities, password)

print("Created new Auth key")
print("Name: " + label)
print("ID: " + str(key.id))
