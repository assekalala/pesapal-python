try:
    import urllib.request as urllib2
except ImportError:
    import urllib2
import re
import pycurl
from io import BytesIO
from OAuth import OAuthSignatureMethod_HMAC_SHA1
from OAuth import OAuthConsumer
from OAuth import OAuthRequest


class PesaPal(object):
    env_url = "http://demo.pesapal.com/api/PostPesapalDirectOrderV4"
    status_url = "https://demo.pesapal.com/api/querypaymentstatus"
    signature_method = "HMAC_SHA1"
    callback_url = ""
    amount = 0
    description = ""
    type_ = ""
    reference = ""
    first_name = ""
    last_name = ""
    email = ""
    phone_number = ""
    token = None
    params = None

    def __init__(self, consumer_key, consumer_secret, env=None):
        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret
        self.env_url = 'http://demo.pesapal.com/api/PostPesapalDirectOrderV4' if env is not None else 'http://www.pesapal.com/api/PostPesapalDirectOrderV4'
    
    def generate_iframe_src(self):
        consumer = OAuthConsumer(self.consumer_key, self.consumer_secret)
        signature_method = OAuthSignatureMethod_HMAC_SHA1()

        post_xml = "<?xml version='1.0' encoding='utf-8'?><PesapalDirectOrderInfo xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' xmlns:xsd='http://www.w3.org/2001/XMLSchema' Amount='%s' Description='%s' Type='%s' Reference='%s' FirstName='%s' LastName='%s' Email='%s' PhoneNumber='%s' xmlns='http://www.pesapal.com' />" % (str(self.amount), self.description, self.type_, self.reference, self.first_name, self.last_name, self.email, self.phone_number)

        iframe_src = OAuthRequest.from_consumer_and_token(consumer, self.token, "GET", self.env_url, self.params)
        iframe_src.set_parameter("oauth_callback", self.callback_url)
        iframe_src.set_parameter("pesapal_request_data", post_xml)
        iframe_src.sign_request(signature_method, consumer, self.token)

        return iframe_src
    

    def check_transaction_status(self, tracking_id, merchant_reference):
        consumer = OAuthConsumer(self.consumer_key, self.consumer_secret)
        signature_method = OAuthSignatureMethod_HMAC_SHA1()
        
        # get transaction status
        request_status = OAuthRequest.from_consumer_and_token(consumer, self.token, "GET", self.status_url, self.params)
        request_status.set_parameter("pesapal_merchant_reference", merchant_reference)
        request_status.set_parameter("pesapal_transaction_tracking_id", tracking_id)
        request_status.sign_request(signature_method, consumer, self.token)

        buffer = BytesIO()

        ch = pycurl.Curl()

        ch.setopt(pycurl.URL, str(request_status))
        ch.setopt(pycurl.WRITEFUNCTION, buffer.write)
        ch.setopt(pycurl.HEADER, True)
        ch.setopt(pycurl.SSL_VERIFYPEER, False)
        ch.setopt(pycurl.SSL_VERIFYHOST, False)


        ch.perform()

        resp = buffer.getvalue()
        header_len = ch.getinfo(pycurl.HEADER_SIZE)
        header = resp[0: header_len]
        body = resp[header_len:]
        elements = body.split('=')
        try:
            status = elements[1]
        except:
            status = "UNKOWN"
        ch.close()

        
        return status