import unittest
import json
from os import environ
from os import urandom

from pymongo import MongoClient

import jwt

# Defer any configuration to the tests setUp()
environ['WHOGOESTHERE_DEFER_CONFIG'] = "True"

import whogoesthere

# Set up TESTING and DEBUG env vars to be picked up by Flask
whogoesthere.app.config['DEBUG'] = True
whogoesthere.app.config['TESTING'] = True
# Set a random secret key for testing
whogoesthere.app.config['SECRET_KEY'] = str(urandom(32))

# Duplicate app config settings into the bp, like the register would
whogoesthere.blueprint.BLUEPRINT.config['DEBUG'] = True
whogoesthere.blueprint.BLUEPRINT.config['TESTING'] = True
whogoesthere.blueprint.BLUEPRINT.config['SECRET_KEY'] = \
    whogoesthere.app.config['SECRET_KEY']

# Don't use these for anything other than tests, duh.
whogoesthere.blueprint.BLUEPRINT.config['PUBLIC_KEY'] = \
    """ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCmuP2ryLX32wqVXoKzE
MjX5JaOSxUnUC3SzuVpzUO0DRvWanKuvV7IhgGPboEWKbcUrSJIfVeGtD9p6Coov
bX7UccaABjIJNd7NB66Y4eizDDxF4Bm4owkmmfESMEsUuVjI8q0Zq7nXhO62B3ix
u+Zo9sGxyHj5bJ292Qu+beX/DVlWUQeOU9i0XJ4YhlOtNQjS8ZURga0Kmh3Ppffv
+lm3IDMdewT35XbcNmsxrPVLykk9s47TwfN0N2/wAEnodZfBZP8if9+QSI6ilxP/
LjXbcXfY1MG8CtTrc/zoic/uODL4j3b6L/qV4bsWvof8imGcRWIDFc83CTW2UCyC
eFR dontuseme"""
whogoesthere.blueprint.BLUEPRINT.config['PRIVATE_KEY'] = \
    """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAprj9q8i199sKlV6CsxDI1+SWjksVJ1At0s7lac1DtA0b1mpy
rr1eyIYBj26BFim3FK0iSH1XhrQ/aegqKL21+1HHGgAYyCTXezQeumOHosww8ReA
ZuKMJJpnxEjBLFLlYyPKtGau514Tutgd4sbvmaPbBsch4+WydvdkLvm3l/w1ZVlE
HjlPYtFyeGIZTrTUI0vGVEYGtCpodz6X37/pZtyAzHXsE9+V23DZrMaz1S8pJPbO
O08HzdDdv8ABJ6HWXwWT/In/fkEiOopcT/y4123F32NTBvArU63P86InP7jgy+I9
2+i/6leG7Fr6H/IphnEViAxXPNwk1tlAsgnhUQIDAQABAoIBAQCKU7wslifcUEGU
ssiQF2H8Ni1wO/1+E7khSgXv5Z3BuoqZONKUBoyopP6QaafyooPDRO7H5C8FlXFz
xmuMR/LAZRZjjScCkAa0swa3sLKtsOr+bXhcZKTQDcgAhDi6NMEbo2ugh/2f+181
S/Bn4pSTDe9AzWFh+4c5y4K0sv3Pu9thoJqgg84tMi0b+r4JVbna8KxiO3A7jwWQ
BeeHYKr99DLd3EK1ZhVAaSs48KBXfekaz4mTnqySo6dNV74hbtUyyws2VStC1o8g
tQjHZWVVh2nGeBTfMkhOAuUenDEAcyue0qB7gsBonn6irU16jBCHpTuAeGEuxoJn
8+NOypX9AoGBANzKrMaJitUTQZp50nEQ8hwWFk5FtV3zDmUwmZ/9dIQ9Obco6RM4
3P86HFFFgJ9leXyaGTq1UmUjtSHgDyQrVAV5IJBAoDH64edFgcZs6WMy8Y772hiH
CiG9OrlSrkNLiT/nCovjgNyQmzsysh+6pBxMqV4Nvz9FyJA2gDsMHqzPAoGBAMFP
ET3VUixcEv/AytPtReJcE1fxmh2Pm5rf9HwOatpDUAtqKchMhacStReEoQ6JYHI2
CG6JRs9MzGru3pETsGKpMBpqZq5QG1+W1sIJe6IWYPVF+Pjt6SgSJwxSB78AiNFA
EuvFNtEGau4eelxEk6LfT7tBRyFRvaOYhFIbuVffAoGAZ+z+ZnVXY/QsbQnqhE31
qEK9PRqSxCYkIH0/0o76yUQIZq5bBzE81OYFbjvIzz50cLIYLgorPnAQUmGkvuGm
Ku1Y5o2E2gG9U57j9wJM2OShzyu8/M6Tdk4b1h+U5xgnAm0+CZqMjUWDy9mQ/l5b
4PY0wpC19JJkVX1R3nlV9wECgYABcT6WsIXJcPJvWBfrVuTjmH5IdLQKrmyhzjP7
zPu9Hy10uFkRdoi0w234e/PbsOi4UXDkqj+OAmuwDJI6kOQLCGokeFDF0jEyGGUH
05xJjFMy4U/HQ7cuplwGOoJ2SWG79fduLO2Ix7x6hF2zXIuhdnsY0ZbfR8Xbd6Ld
HfnXDwKBgCpfy32fyk4wpqhgisdbHVqt89QLIw+6I5pVy/vW7oB6s8ZaDaRzpx62
AUyLcfa1WTibE8n9Ih7BPE8EtL4KUyk15MBRGMeOgsjCRoIcmL6OssyqTYXlIbYr
2BkwsDueSsMfqSCKitaXfyt4Gc/3vtB60D3JWzZ8cEENVNEfhclD
-----END RSA PRIVATE KEY-----"""


class Tests(unittest.TestCase):
    def setUp(self):
        # Perform any setup that should occur
        # before every test
        # Run a local mongo on 27017 for testing
        # docker run -p 27017:27017 mongo <-- fire one up with docker if required
        self.client = MongoClient('localhost', 27017)
        whogoesthere.blueprint.BLUEPRINT.config['authentication_db'] = \
            self.client['whogoesthere_test']
        whogoesthere.blueprint.BLUEPRINT.config['authorization_db'] = \
            self.client['whogoesthere_test']
        self.app = whogoesthere.app.test_client()

    def tearDown(self):
        # Perform any tear down that should
        # occur after every test
        self.client.drop_database('whogoesthere_test')
        del self.client
        del self.app

    def testPass(self):
        self.assertEqual(True, True)

    def testVersionAvailable(self):
        x = getattr(whogoesthere, "__version__", None)
        self.assertTrue(x is not None)

    def testVersion(self):
        version_response = self.app.get("/version")
        self.assertEqual(version_response.status_code, 200)
        version_json = json.loads(version_response.data.decode())
        api_reported_version = version_json['version']
        self.assertEqual(
            whogoesthere.blueprint.__version__,
            api_reported_version
        )

    def test_pubkey(self):
        pubkey_response = self.app.get("/pubkey")
        self.assertEqual(pubkey_response.status_code, 200)
        pubkey = pubkey_response.data.decode()
        self.assertEqual(
            whogoesthere.blueprint.BLUEPRINT.config['PUBLIC_KEY'],
            pubkey
        )

    def test_make_user(self):
        make_user_response = self.app.post("/make_user",
                                           data={'user': "foo", 'pass': "bar"})
        self.assertEqual(make_user_response.status_code, 200)
        make_user_json = json.loads(make_user_response.data.decode())
        self.assertEqual(make_user_json['success'], True)

    def test_user_bounce(self):
        self.test_make_user()
        make_user_response = self.app.post("/make_user",
                                           data={'user': "foo", 'pass': "bar"})
        self.assertEqual(make_user_response.status_code, 403)

    def test_make_and_authenticate(self):
        self.test_make_user()
        authentication_response = self.app.get("/auth_user",
                                               data={'user': 'foo', 'pass': 'bar'})
        self.assertEqual(authentication_response.status_code, 200)
        authentication_token = authentication_response.data.decode()
        decoded_token = jwt.decode(
            authentication_token,
            whogoesthere.blueprint.BLUEPRINT.config['PUBLIC_KEY'],
            algorithm='RS256'
        )
        self.assertEqual(decoded_token['user'], 'foo')

    def test_bad_login(self):
        self.test_make_user()
        authentication_response = self.app.get("/auth_user",
                                               data={'user': 'foo', 'pass': 'bazz'})
        self.assertEqual(authentication_response.status_code, 404)

    def test_nonexistant_user(self):
        authentication_response = self.app.get("/auth_user",
                                               data={'user': 'nothere', 'pass': 'a'})
        self.assertEqual(authentication_response.status_code, 404)

    def test_validate_token(self):
        self.test_make_user()
        authentication_response = self.app.get("/auth_user",
                                               data={'user': 'foo', 'pass': 'bar'})
        self.assertEqual(authentication_response.status_code, 200)
        authentication_token = authentication_response.data.decode()
        token_check_response = self.app.get("/check", data={'token': authentication_token})
        self.assertEqual(token_check_response.status_code, 200)
        token_check_json = json.loads(token_check_response.data.decode())
        self.assertEqual(token_check_json['token_status'], 'valid')

    def test_invalid_token(self):
        self.test_make_user()
        authentication_response = self.app.get("/auth_user",
                                               data={'user': 'foo', 'pass': 'bar'})
        self.assertEqual(authentication_response.status_code, 200)
        authentication_token = authentication_response.data.decode()
        if authentication_token[0] != 'a':
            authentication_token = 'a' + authentication_token[1:]
        else:
            authentication_token = 'b' + authentication_token[1:]
        token_check_response = self.app.get("/check", data={'token': authentication_token})
        self.assertEqual(token_check_response.status_code, 200)
        token_check_json = json.loads(token_check_response.data.decode())
        self.assertEqual(token_check_json['token_status'], 'invalid')


if __name__ == "__main__":
    unittest.main()
