from oic.oic.message import IdToken as OICIDToken
from jwkest.jws import JWS


class IdToken(OICIDToken):
    def to_jwt(self, key=None, algorithm="", lev=0):
        """
        Create a signed JWT representation of the class instance.
        :param key: The signing key
        :param algorithm: The signature algorithm to use
        :return: A signed JWT
        """
        _jws = JWS(self.to_json(lev), alg=algorithm, typ='JWT')
        return _jws.sign_compact(key)
