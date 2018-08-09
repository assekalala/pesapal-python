# Pesapal Python
A python package to interact with [Pesapal](https://www.pesapal.com) APIs


### Installation
```
pip install pesapal
```

### Usage example
To generate iframe source

```python
from pesapal.pesapal import PesaPal

consumer_key = 'YOUR-CONSUMER-KEY'
consumer_secret = 'YOUR-CONSUMER-SECRET'
    

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

```

To check transaction status
```python
status = pesapal.check_transaction_status('45457fyfws65', 'TXN1234')
print("STATUS: %s" % status)
```
