import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="pesapal",
    version="0.0.1",
    author="Abdu Ssekalala",
    author_email="assekalala@gmail.com",
    description="A module to interact with PesaPal REST apis, www.pesapal.com",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/assekalala/pesapal-python",
    packages=setuptools.find_packages(),
    install_requires=[
      'natsort',
      'pycurl',
      'pyopenssl',
    ]
    classifiers=(
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ),
)