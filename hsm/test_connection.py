from yubihsm import YubiHsm

serverip = "127.0.0.1"
port = 12345
authid = 1
password= "password"

hsm = YubiHsm.connect(f"http://{serverip}:{port}/api")
session = hsm.create_session_derived(authid, password)

