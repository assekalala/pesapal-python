from pesapal.pesapal import PesaPal

consumer_key = 'xxxxxxxxxx'
consumer_secret = 'xxxxxxxx'
    

pesapal = PesaPal(consumer_key, consumer_secret, 'sandbox')
pesapal.amount = 1000
pesapal.description = 'description'
pesapal.type_ = 'MERCHANT'
pesapal.reference = 'TXN12345'
pesapal.first_name = 'John'
pesapal.last_name = 'Doe'
pesapal.phone_number = '256772123456'
pesapal.email = 'john@example.com'
pesapal.callback_url = 'http://www.yourdomain.com/redirect.php'
iframe_src = pesapal.generate_iframe_src()

print(iframe_src)


status = pesapal.check_transaction_status('45457fyfws65', 'TXN1234')
print("STATUS: %s" % status)
