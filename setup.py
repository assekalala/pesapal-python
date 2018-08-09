from setuptools import setup

def readme():
    with open('readme.md') as f:
        return f.read()

setup(
  name = 'pesapal',
  version = '1.0',
  description = 'A module to interact with PesaPal REST apis, www.pesapal.com',
  long_description = readme(),
  author = 'Abdu Ssekalala',
  author_email = 'assekalala@gmail.com',
  url = 'https://github.com/assekalala/pesapal-python.git',
  keywords = ['pesapal', 'payments'],
  py_modules = ['pesapal'],
  classifiers = [
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Communications",
        "Development Status :: 1 - Beta"
  ],
)
