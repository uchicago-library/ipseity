import unittest
import json
from os import environ
from os import urandom
from time import sleep

from pymongo import MongoClient, ASCENDING

import jwt

import flask_jwtlib

# Defer any configuration to the tests setUp()
environ['IPSEITY_DEFER_CONFIG'] = "True"

import ipseity

# Set up TESTING and DEBUG env vars to be picked up by Flask
ipseity.app.config['DEBUG'] = True
ipseity.app.config['TESTING'] = True
# Set a random secret key for testing
ipseity.app.config['SECRET_KEY'] = str(urandom(32))

# Duplicate app config settings into the bp, like the register would
ipseity.blueprint.BLUEPRINT.config['DEBUG'] = True
ipseity.blueprint.BLUEPRINT.config['TESTING'] = True
ipseity.blueprint.BLUEPRINT.config['SECRET_KEY'] = \
    ipseity.app.config['SECRET_KEY']


class Mixin:
    def setUp(self):
        # Perform any setup that should occur
        # before every test
        # Run a local mongo on 27017 for testing
        # docker run -p 27017:27017 mongo <-- fire one up with docker if required
        self.client = MongoClient('localhost', 27017)
        ipseity.blueprint.BLUEPRINT.config['authentication_coll'] = \
            self.client['ipseity_test']['authentication']
        # Mimic index creation which usually happens at bootstrap
        ipseity.blueprint.BLUEPRINT.config['authentication_coll'].create_index(
                    [('user', ASCENDING)],
                    unique=True
                )

        BLUEPRINT = ipseity.blueprint.BLUEPRINT
        API = ipseity.blueprint.API
        PublicKey = ipseity.blueprint.PublicKey

        if BLUEPRINT.config['ALGO'] not in jwt.algorithms.get_default_algorithms():
            raise RuntimeError(
                "Unsupported algorithm, select one of: {}".format(
                    ", ".join(x for x in jwt.algorithms.get_default_algorithms().keys())
                )
            )

        asymmetric_algos = [
            'PS256',
            'PS384',
            'PS512',
            'RS256',
            'RS384',
            'RS512',
            'ES256',
            'ES384',
            'ES512'
        ]

        if BLUEPRINT.config['ALGO'] in asymmetric_algos:
            if BLUEPRINT.config.get("PRIVATE_KEY") is None or \
                    BLUEPRINT.config.get("PUBLIC_KEY") is None:
                raise RuntimeError(
                    "Asymmetric algos must specify both IPSEITY_PRIVATE_KEY " +
                    "and IPSEITY_PUBLIC_KEY"
                )
            BLUEPRINT.config['SIGNING_KEY'] = BLUEPRINT.config['PRIVATE_KEY']
            BLUEPRINT.config['VERIFY_KEY'] = BLUEPRINT.config['PUBLIC_KEY']
            flask_jwtlib.set_permanent_verification_key(BLUEPRINT.config['PUBLIC_KEY'])
            try:
                API.add_resource(PublicKey, "/pubkey")
            except:
                pass
        else:
            BLUEPRINT.config['SIGNING_KEY'] = BLUEPRINT.config['PRIVATE_KEY']
            BLUEPRINT.config['VERIFY_KEY'] = BLUEPRINT.config['PRIVATE_KEY']
            flask_jwtlib.set_permanent_verification_key(BLUEPRINT.config['PRIVATE_KEY'])

        flask_jwtlib.JWT_ALGO = ipseity.blueprint.BLUEPRINT.config['ALGO']
        self.app = ipseity.app.test_client()

    def tearDown(self):
        # Perform any tear down that should
        # occur after every test
        self.client.drop_database('ipseity_test')
        del self.client
        del self.app

    def testPass(self):
        self.assertEqual(True, True)

    def testRoot(self):
        r = self.app.get("/")
        self.assertEqual(r.status_code, 200)

    def testVersionAvailable(self):
        x = getattr(ipseity, "__version__", None)
        self.assertTrue(x is not None)

    def testVersion(self):
        version_response = self.app.get("/version")
        self.assertEqual(version_response.status_code, 200)
        version_json = json.loads(version_response.data.decode())
        api_reported_version = version_json['version']
        self.assertEqual(
            ipseity.blueprint.__version__,
            api_reported_version
        )

    def test_pubkey(self):
        pubkey_response = self.app.get("/pubkey")
        self.assertEqual(pubkey_response.status_code, 200)
        pubkey = pubkey_response.data.decode()
        self.assertEqual(
            ipseity.blueprint.BLUEPRINT.config['VERIFY_KEY'],
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
            ipseity.blueprint.BLUEPRINT.config['VERIFY_KEY'],
            algorithm=ipseity.blueprint.BLUEPRINT.config['ALGO']
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
        token_check_response = self.app.get("/check", data={'access_token': authentication_token})
        self.assertEqual(token_check_response.status_code, 200)
        token_check_json = json.loads(token_check_response.data.decode())
        self.assertEqual(token_check_json['user'], 'foo')

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
        self.assertEqual(token_check_response.status_code, 400)

    def test_decoratored_endpoint(self):
        self.test_make_user()
        authentication_response = self.app.get("/auth_user",
                                               data={'user': 'foo', 'pass': 'bar'})
        self.assertEqual(authentication_response.status_code, 200)
        authentication_token = authentication_response.data.decode()
        test_response = self.app.get("/test", data={"access_token": authentication_token})
        self.assertEqual(test_response.status_code, 200)

    def test_change_pass(self):
        self.test_make_user()
        authentication_response = self.app.get("/auth_user",
                                               data={'user': 'foo', 'pass': 'bar'})
        self.assertEqual(authentication_response.status_code, 200)
        authentication_token = authentication_response.data.decode()

        # Change the password
        change_pass_response = self.app.post(
            "/change_pass",
            data={
                "new_pass": "baz",
                "access_token": authentication_token
            }
        )

        # Test to be sure the new password is valid
        self.assertEqual(change_pass_response.status_code, 200)
        authentication_response = self.app.get("/auth_user",
                                               data={'user': 'foo', 'pass': 'baz'})
        self.assertEqual(authentication_response.status_code, 200)

        # Test to be sure the old password is now invalid
        self.assertEqual(change_pass_response.status_code, 200)
        authentication_response = self.app.get("/auth_user",
                                               data={'user': 'foo', 'pass': 'bar'})
        self.assertEqual(authentication_response.status_code, 404)

    def test_delete_account(self):
        self.test_make_user()
        authentication_response = self.app.get("/auth_user",
                                               data={'user': 'foo', 'pass': 'bar'})
        self.assertEqual(authentication_response.status_code, 200)
        access_token = authentication_response.data.decode()

        del_self_response = self.app.delete(
            "/del_user",
            data={'access_token': access_token}
        )
        self.assertEqual(del_self_response.status_code, 200)

        authentication_response = self.app.get("/auth_user",
                                               data={'user': 'foo', 'pass': 'bar'})
        self.assertEqual(authentication_response.status_code, 404)

    def test_refresh_token(self):
        self.test_make_user()
        # Get an access token
        authentication_response = self.app.get("/auth_user",
                                               data={'user': 'foo', 'pass': 'bar'})
        self.assertEqual(authentication_response.status_code, 200)
        access_token = authentication_response.data.decode()
        # Use our first access token to generate a refresh token
        refresh_token_response = self.app.get("/refresh_token",
                                              data={'access_token': access_token})
        self.assertEqual(refresh_token_response.status_code, 200)
        refresh_token = refresh_token_response.data.decode()
        # Use the refresh token to get a new access token
        second_authentication_response = self.app.get("/auth_user",
                                                      data={'user': refresh_token})
        self.assertEqual(second_authentication_response.status_code, 200)
        second_access_token = second_authentication_response.data.decode()
        # Use our second access token to remove the refresh token
        deactivate_refresh_response = self.app.delete(
            "/refresh_token",
            data={
                "access_token": second_access_token,
                "refresh_token": refresh_token
            }
        )
        self.assertEqual(deactivate_refresh_response.status_code, 200)
        # Be sure we can't use that refresh token anymore
        # We get a 400 when we try
        third_auth_attempt_response = self.app.get("/auth_user",
                                                   data={"user": refresh_token})
        self.assertEqual(third_auth_attempt_response.status_code, 400)

    def test_token_limitations(self):
        self.test_make_user()
        # Get an access token
        authentication_response = self.app.get("/auth_user",
                                               data={'user': 'foo', 'pass': 'bar'})
        self.assertEqual(authentication_response.status_code, 200)
        access_token = authentication_response.data.decode()
        # Use our first access token to generate a refresh token
        refresh_token_response = self.app.get("/refresh_token",
                                              data={'access_token': access_token})
        self.assertEqual(refresh_token_response.status_code, 200)
        refresh_token = refresh_token_response.data.decode()
        # Use the refresh token to get a new access token
        second_authentication_response = self.app.get("/auth_user",
                                                      data={'user': refresh_token})
        self.assertEqual(second_authentication_response.status_code, 200)
        second_access_token = second_authentication_response.data.decode()

        # Now that we've got our refresh token based access token, lets
        # try to do all the things we can't.
        delete_me_response = self.app.delete("/del_user",
                                             data={'access_token': second_access_token})
        self.assertEqual(delete_me_response.status_code, 403)

        new_refresh_token_response = self.app.get("/refresh_token",
                                                  data={'access_token': second_access_token})
        self.assertEqual(new_refresh_token_response.status_code, 403)

        chpass_response = self.app.post("/change_pass",
                                        data={'access_token': second_access_token,
                                              'new_pass': 'buzz'})
        self.assertEqual(chpass_response.status_code, 403)

    def test_refresh_token_as_access_token(self):
        self.test_make_user()
        # Get an access token
        authentication_response = self.app.get("/auth_user",
                                               data={'user': 'foo', 'pass': 'bar'})
        self.assertEqual(authentication_response.status_code, 200)
        access_token = authentication_response.data.decode()
        # Use our first access token to generate a refresh token
        refresh_token_response = self.app.get("/refresh_token",
                                              data={'access_token': access_token})
        self.assertEqual(refresh_token_response.status_code, 200)
        refresh_token = refresh_token_response.data.decode()

        # Try to use a refresh token as an access_token
        refresh_as_access_response = self.app.get("/check",
                                                  data={'access_token': refresh_token})
        self.assertEqual(refresh_as_access_response.status_code, 400)

        # Try to use an access token as a refresh_token
        access_as_refresh_response = self.app.get("/auth_user",
                                                  data={'user': access_token})
        self.assertEqual(access_as_refresh_response.status_code, 400)

    def test_expired_refresh_token(self):
        ipseity.blueprint.BLUEPRINT.config['REFRESH_EXP_DELTA'] = 5
        self.test_make_user()
        # Get an access token
        authentication_response = self.app.get("/auth_user",
                                               data={'user': 'foo', 'pass': 'bar'})
        self.assertEqual(authentication_response.status_code, 200)
        access_token = authentication_response.data.decode()
        # Use our first access token to generate a refresh token
        refresh_token_response = self.app.get("/refresh_token",
                                              data={'access_token': access_token})
        self.assertEqual(refresh_token_response.status_code, 200)
        refresh_token = refresh_token_response.data.decode()
        sleep(7)  # Let the refresh token expire
        second_authentication_response = self.app.get("/auth_user",
                                                      data={'user': refresh_token})
        self.assertEqual(second_authentication_response.status_code, 400)
        del ipseity.blueprint.BLUEPRINT.config['REFRESH_EXP_DELTA']

    def test_expired_access_token(self):
        ipseity.blueprint.BLUEPRINT.config['ACCESS_EXP_DELTA'] = 5
        self.test_make_user()
        # Get an access token
        authentication_response = self.app.get("/auth_user",
                                               data={'user': 'foo', 'pass': 'bar'})
        self.assertEqual(authentication_response.status_code, 200)
        access_token = authentication_response.data.decode()
        sleep(7)
        check_response = self.app.get("/check",
                                      data={'access_token': access_token})
        self.assertEqual(check_response.status_code, 400)
        del ipseity.blueprint.BLUEPRINT.config['ACCESS_EXP_DELTA']

    def test_disallowed_token_pruning(self):
        ipseity.blueprint.BLUEPRINT.config['REFRESH_EXP_DELTA'] = 10
        self.test_make_user()
        # Get an access token
        authentication_response = self.app.get("/auth_user",
                                               data={'user': 'foo', 'pass': 'bar'})
        self.assertEqual(authentication_response.status_code, 200)
        access_token = authentication_response.data.decode()
        # Use our first access token to generate a lot of refresh tokens
        refresh_tokens = []
        for _ in range(50):
            refresh_token_response = self.app.get("/refresh_token",
                                                  data={'access_token': access_token})
            self.assertEqual(refresh_token_response.status_code, 200)
            refresh_tokens.append(refresh_token_response.data.decode())
        # Then delete them all
        for x in refresh_tokens:
            refresh_token_delete_response = \
                self.app.delete("/refresh_token",
                                data={"access_token": access_token,
                                      "refresh_token": x})
            self.assertEqual(refresh_token_delete_response.status_code, 200)
        # grab our user document now - all the deleted tokens should be in there
        user_doc = ipseity.blueprint.BLUEPRINT.config['authentication_coll'].find_one(
            {"user": "foo"}
        )
        self.assertEqual(len(user_doc['disallowed_tokens']), 50)
        # Wait for them to expire
        sleep(11)
        # Fire a functionality which prunes the database
        # [authentication, getting a refresh token, deleting a refresh token]
        # We'll use authentication
        second_access_token_response = self.app.get("/auth_user",
                                                    data={"user": "foo", "pass": "bar"})
        self.assertEqual(second_access_token_response.status_code, 200)
        # Now grab the user document again, the old tokens should be pruned
        user_doc = ipseity.blueprint.BLUEPRINT.config['authentication_coll'].find_one(
            {"user": "foo"}
        )
        self.assertEqual(len(user_doc['disallowed_tokens']), 0)

    def test_unauthorized_access(self):
        for x in ("/test", "/refresh_token"):
            r = self.app.get(x)
            self.assertEqual(r.status_code, 401)
        r = self.app.delete("/del_user")
        self.assertEqual(r.status_code, 401)
        r = self.app.post("/change_pass")
        self.assertEqual(r.status_code, 401)

    def test_malformed_token(self):
        r = self.app.get("/test",
                         data={"access_token": "abc123"})
        self.assertEqual(r.status_code, 401)

    def test_delete_access_token(self):
        self.test_make_user()
        # Get an access token
        authentication_response = self.app.get("/auth_user",
                                               data={'user': 'foo', 'pass': 'bar'})
        self.assertEqual(authentication_response.status_code, 200)
        access_token = authentication_response.data.decode()
        delete_access_token_response = \
            self.app.delete(
                "/refresh_token",
                data={
                    "access_token": access_token,
                    "refresh_token": access_token
                }
            )
        self.assertEqual(delete_access_token_response.status_code, 400)

    def test_delete_nonexistant_refresh_token(self):
        self.test_make_user()
        # Get an access token
        authentication_response = self.app.get("/auth_user",
                                               data={'user': 'foo', 'pass': 'bar'})
        self.assertEqual(authentication_response.status_code, 200)
        access_token = authentication_response.data.decode()
        delete_bad_token_response = \
            self.app.delete(
                "/refresh_token",
                data={
                    "access_token": access_token,
                    "refresh_token": "abc123"
                }
            )
        self.assertEqual(delete_bad_token_response.status_code, 400)


class AsymmetricTests(Mixin, unittest.TestCase):
    def setUp(self):
        ipseity.blueprint.BLUEPRINT.config['ALGO'] = "RS256"

        # Don't use these for anything other than tests, duh.

        ipseity.blueprint.BLUEPRINT.config['PUBLIC_KEY'] = \
            """ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCmuP2ryLX32wqVXoKzE
MjX5JaOSxUnUC3SzuVpzUO0DRvWanKuvV7IhgGPboEWKbcUrSJIfVeGtD9p6Coov
bX7UccaABjIJNd7NB66Y4eizDDxF4Bm4owkmmfESMEsUuVjI8q0Zq7nXhO62B3ix
u+Zo9sGxyHj5bJ292Qu+beX/DVlWUQeOU9i0XJ4YhlOtNQjS8ZURga0Kmh3Ppffv
+lm3IDMdewT35XbcNmsxrPVLykk9s47TwfN0N2/wAEnodZfBZP8if9+QSI6ilxP/
LjXbcXfY1MG8CtTrc/zoic/uODL4j3b6L/qV4bsWvof8imGcRWIDFc83CTW2UCyC
eFR dontuseme"""
        ipseity.blueprint.BLUEPRINT.config['PRIVATE_KEY'] = \
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

        super().setUp()

    def tearDown(self):
        del ipseity.blueprint.BLUEPRINT.config['PUBLIC_KEY']
        del ipseity.blueprint.BLUEPRINT.config['PRIVATE_KEY']
        del ipseity.blueprint.BLUEPRINT.config['ALGO']

        super().tearDown()


class SymmetricTests(Mixin, unittest.TestCase):
    def setUp(self):
        ipseity.blueprint.BLUEPRINT.config['ALGO'] = "HS256"
        ipseity.blueprint.BLUEPRINT.config['PRIVATE_KEY'] = \
            str(urandom(32))
        super().setUp()

    def tearDown(self):
        del ipseity.blueprint.BLUEPRINT.config['ALGO']
        del ipseity.blueprint.BLUEPRINT.config['PRIVATE_KEY']
        super().tearDown()

    def test_pubkey(self):
        pubkey_response = self.app.get("/pubkey")
        self.assertEqual(pubkey_response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
