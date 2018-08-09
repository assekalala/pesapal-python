try:
    import urllib.request as urllib2
except ImportError:
    import urllib2

import base64
import time
import uuid
import hmac
import itertools
import urllib
from urlparse import urlparse
from hashlib import sha1
from utils import *


class OAuthException(Exception):
    pass


class OAuthConsumer(object):
    def __init__(self, key, secret, callback_url=None):
        self.key = key
        self.secret = secret
        self.callback_url = callback_url
    
    def __str__(self):
        return "OAuthConsumer[key=%s,secret=%s]" % (self.key, self.secret)

class OAuthToken(object):
    def __init__(self, key, secret):
        self.key = key
        self.secret = secret

    def to_string(self):
        return "oauth_token=%s&oauth_token_secret=%s" % (OAuthUtil.urlencode_rfc3986(self.key), OAuthUtil.urlencode_rfc3986(self.secret))

    def __str__(self):
        self.to_string()


class OAuthSignatureMethod(object):

    def check_signature(self, request, consumer, token, signature):
        built = self.build_signature(request, consumer, token)
        return built == signature

class OAuthSignatureMethod_HMAC_SHA1(OAuthSignatureMethod):

    def get_name(self):
        return "HMAC-SHA1"

    def build_signature(self, request, consumer, token):
        base_string = request.get_signature_base_string()
        request.base_string = base_string
        
        key_parts = [
            consumer.secret,
            token.secret if not (token is None) else ""
        ]


        key_parts = OAuthUtil.urlencode_rfc3986(key_parts)
        key = '&'.join(key_parts)

        hashed = hmac.new(key, base_string, sha1)

        return hashed.digest().encode("base64").rstrip('\n')

class OAuthSignatureMethod_PLAINTEXT(OAuthSignatureMethod):
    def get_name(self):
        return "PLAINTEXT"

    def build_signature(self, request, consumer, token):
        sig = [
            OAuthUtil.urlencode_rfc3986(consumer.secret)
        ]

        if (token):
            pass
        else:
            pass

        raw = '&'.join(sig)
        # for debug purposes
        request.base_string = raw

        return OAuthUtil.urlencode_rfc3986(raw)

class OAuthSignatureMethod_RSA_SHA1(OAuthSignatureMethod):
    def get_name(self):
        return "RSA-SHA1"

    def fetch_public_cert(self, request):
        # not implemented yet, ideas are:
        # (1) do a lookup in a table of trusted certs keyed off of consumer
        # (2) fetch via http using a url provided by the requester
        # (3) some sort of specific discovery code based on request
        #
        # either way should return a string representation of the certificate
        raise Exception("fetch_public_cert not implemented")
    
    def fetch_private_cert(self, request):
        # not implemented yet, ideas are:
        # (1) do a lookup in a table of trusted certs keyed off of consumer
        #
        # either way should return a string representation of the certificate
        raise Exception("fetch_private_cert not implemented")

    def build_signature(self, request, consumer, token):
        base_string = request.get_signature_base_string()
        request.base_string = base_string

        # Fetch the private key cert based on the request
        cert = self.fetch_private_cert(request)

        # Pull the private key ID from the certificate
        privatekeyid = openssl_get_privatekey(cert)

        # Sing using the key
        ok = openssl_sign(base_string, signature, privatekeyid)

        # Release the key resource
        openssl_free_key(privatekeyid)

        return base64.b64encode(signature)

    def check_signature(self, request, consumer, token, signature):
        decoded_sig = base64.b64decode(signature)

        base_string = request.get_signature_base_string()

        # Fetch the public key cert base on the request
        cert = self.fetch_public_cert(request)

        # Pull the public key ID from the certificate
        publickeyid = openssl_get_publickey(cert)

        # Check the computed signature against the one passed in the query
        ok = openssl_verify(base_string, decoded_sig, publickeyid)

        # Release the key resource
        openssl_free_key(publickeyid)

        return ok -- 1

class OAuthRequest(object):
    version = '1.0'
    parameters = {}

    def __init__(self, http_method, http_url, parameters=None):
        self.parameters = parameters
        self.http_method = http_method
        self.http_url = http_url

    def from_request(self, http_method=None, http_url=None, parameters=None):
        pass
    
    @staticmethod
    def from_consumer_and_token(consumer, token, http_method, http_url, parameters=None):
        if not parameters:
            parameters = {}

        defaults = {
            "oauth_version": OAuthRequest.version,
            "oauth_nonce": OAuthRequest.generate_nonce(),
            "oauth_timestamp": OAuthRequest.generate_timestamp(),
            "oauth_consumer_key": consumer.key
        }
        if not (token is None):
            defaults['oauth_token'] = token.key
        
        parameters = merge_two_dicts(defaults, parameters)

        return OAuthRequest(http_method, http_url, parameters)
    
    def set_parameter(self, name, value, allow_duplicates=True):
        
        if(allow_duplicates == True and self.parameters.has_key(name)):
            # We have already added parameter(s) with this name, so add to the list
            if(isinstance(self.parameters[name], list) == False):
                # This is the first duplicate, so transform scalar (string)
                # into an array so we can add the duplicates
                self.parameters[name] = [self.parameters[name]]
            self.parameters[name] = value
        else:
            self.parameters[name] = value
        
    
    def get_parameter(self, name):
        return self.parameters[name] if (self.parameters[name] != None) else  None

    def get_parameters(self):
        return self.parameters

    def unset_parameter(self, name):
        pass
    
    def get_signable_parameters(self):
        # Grab all parameters
        params = self.parameters

        # Remove oauth_signature if present
        # Ref: Spec: 9.1.1 ("he oauth_signature parameter MUST be excluded.")
        if params.has_key('oauth_signature'):
            del params['oauth_signature']

        return OAuthUtil.build_http_query(params)

    def get_signature_base_string(self):
        parts = [
            self.get_normalized_http_method(),
            self.get_normalized_http_url(),
            self.get_signable_parameters()
        ]

        parts = OAuthUtil.urlencode_rfc3986(parts)
        return '&'.join(parts)
    
    def get_normalized_http_method(self):
        return self.http_method.upper()

    def get_normalized_http_url(self):
        parts = urlparse(self.http_url)

        port = parts.port
        scheme = parts.scheme
        host = parts.hostname
        path = parts.path

        port = '443' if (scheme == 'https') else '80'
        # print("port: %s" % port)

        # if ((scheme == 'https' and port != '443') or (scheme == 'https' and port != '80')):
        #     host = "%s:%s" % (host, port)

        return "%s://%s%s" % (scheme, host, path)

    def to_url(self):
        post_data = self.to_postdata()
        out = self.get_normalized_http_url()

        if(post_data):
            out += '?' + post_data
        
        return out

    def to_postdata(self):
        return OAuthUtil.build_http_query(self.parameters)

    def to_header(self):
        out = 'Authorization: OAuth realm=""'
        total = []

        for k, v in self.parameters.iteritems():
            pass
        
        return out

    def sign_request(self, signature_method, consumer, token):
        self.set_parameter("oauth_signature_method", signature_method.get_name(), False)
        signature = self.build_signature(signature_method, consumer, token)
        self.set_parameter("oauth_signature", signature, False)

    def build_signature(self, signature_method, consumer, token):
        signature = signature_method.build_signature(self, consumer, token)
        return signature
    
    @staticmethod
    def generate_timestamp():
        return int(time.time())
    
    @staticmethod
    def generate_nonce():
        return str(uuid.uuid4()) #.replace('-','')

    def __str__(self):
        return self.to_url()

class OAuthServer(object):
    timestamp_threshold = 300
    version = 1.0
    signature_methods = []

    def __init__(self, data_store):
        self.data_store = data_store

    def add_signature_method(self, signature_method):
        self.signature_methods[signature_method.get_name()] = signature_method

    def fetch_request_token(self, request):
        self.get_version(request)

        consumer = self.get_consumer(request)

        token = None

        self.check_signature(request, consumer, token)

        new_token = self.data_store.new_request_token(consumer)

        return new_token
    
    def fetch_access_token(self, request):
        self.get_version(request)

        consumer = self.get_consumer(request)

        # requires authorized request token
        token = self.get_token(request, consumer, "request")

        self.check_signature(request, consumer, token)

        new_token = self.data_store.new_access_token(token)

        return new_token

    # #
    # verify an api call, checks all the parameters
    # #
    def verify_request(self, request):
        self.get_version(request)
        consumer = self.get_consumer(request)
        token = self.get_token(request, consumer, "access")
        self.check_signature(request, consumer, token)
        return [consumer, token]

    def get_version(self, request):
        version = request.get_parameter("oauth_version")

        if (version is not None):
            version = 1.0

        if (version != self.version):
            raise OAuthException(("OAuth version %s not supported" % version)) 

        return version

    def get_signature_method(self, request):
        signature_method = request.get_parameter("oauth_signature_method")

        if (signature_method is None):
            signature_method = "PLAINTEXT"

        return self.signature_methods[signature_method]

    def get_consumer(self, request):
        consumer_key = request.get_parameter("oauth_consumer_key")

        if (consumer_key is None):
            raise OAuthException("Invalid consumer key")

        consumer = self.data_store.lookup_consumer(consumer_key)

        if (consumer is None):
            raise OAuthException("Invalid consumer")

        return consumer

    def get_token(self, request, consumer, token_type="access"):
        pass

    def check_signature(self, request, consumer, token):
        pass
    
    def check_timestamp(self, timestamp):
        pass

    def check_nonce(self, consumer, token, nonce):
        pass


class OAuthDataStore(object):

    def lookup_consumer(self, consumer_key):
        pass
    
    def lookup_token(self, consumer, token_type, token):
        pass

    def lookup_nonce(self, consumer, token, nonce, timestamp):
        pass

    def new_request_token(self, consumer):
        pass

    def new_access_token(self, token, consumer):
        pass

class OAuthUtil(object):

    @staticmethod
    def urlencode_rfc3986(input):
        if (isinstance(input, list) == True):
            return map(OAuthUtil.urlencode_rfc3986, input)
        elif (isinstance(input, list) == False):
            
            raw_encoded_string = urllib.quote(unicode(str(input), "utf-8"), safe='').replace("%7E", " ")
            
            return str(raw_encoded_string).replace("+", " ")
        else:
            return ''

    @staticmethod
    def urldecode_rfc3986(string):
        return urllib.urldecode(string)
    
    def split_header(self, header, only_allow_oauth_parameters=True):
        pattern = '/(([-_a-z]*)=("([^"]*)"|([^,]*)),?)/'
        offset = 0
        params = {}

        # while (preg_match(pattern, header, matches, PREG_OFFSET_CAPTURE, offset) > 0):
        #     match = matches[0]
        #     header_name = matches[2][0]
        #     header_content =  matches[5][0] if (isset(matches[5])) else matches[4][0]
        #     if (preg_match('/^oauth_/', header_name) or !only_allow_oauth_parameters):
        #         params[header_name] = OAuthUtil::urldecode_rfc3986(header_content)
        #     offset = match[1] + strlen(match[0])

        if (params.has_key('realm')):
            del params['realm']

        return params

    def get_headers(self):
        pass

    def parse_parameters(self, input):
        pass

    @staticmethod
    def build_http_query(params):
        if not params: return ''

        # # Urlencode both keys and values
        keys = OAuthUtil.urlencode_rfc3986(params.keys())
        values = OAuthUtil.urlencode_rfc3986(params.values())
        params = dict(itertools.izip(keys,values))

        # # Parameters are sorted by name, using lexicographical byte value ordering.
        # # Ref: Spec: 9.1.1 (1)
        # uksort(params, 'strcmp')

        pairs = []
        for parameter, value in params.iteritems():
            if isinstance(value, list):
                # If two or more parameters share the same name, they are sorted by their value
                # Ref: Spec: 9.1.1 (1)
                natsort(value)
                for duplicate_value in value:
                    pairs.append(parameter + '=' + duplicate_value)
            else:
                pairs.append(parameter + '=' + value)


        
        # # For each parameter, the name is separated from
        # # Each name-value pair is seperated by an '&' character
        
        return '&'.join(sorted(pairs))