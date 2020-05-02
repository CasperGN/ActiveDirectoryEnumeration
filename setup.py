import setuptools

with open('README.md', 'r') as desc:
    long_desc = desc.read()

setuptools.setup(
        name = 'ActiveDirectoryEnum',
        version = '0.3.0',
        author = 'Casper G. Nielsen',
        author_email = 'whopsec@protonmail.com',
        description = 'Enumerate Active Directory with standard vectors',
        long_description = long_desc,
        long_description_content_type = 'text/markdown',
        url = 'https://github.com/CasperGN/ActiveDirectoryEnumeration',
        packages = setuptools.find_packages(),
        install_reqs = [
            "cffi",
            "Click",
            "cryptography",
            "Crypto",
            "dnspython",
            "Flask",
            "future",
            "impacket",
            "itsdangerous",
            "Jinja2",
            "ldap3",
            "ldapdomaindump",
            "MarkupSafe",
            "progressbar",
            "pyasn1"
            "pycparser",
            "pycryptodomex",
            "pyOpenSSL",
            "six",
            "termcolor",
            "Werkzeug",
        ],
        classifiers = [
            'Programming Language :: Python :: 3',
            'License :: OSI Approved :: MIT License',
        ],
        python_requires = '>=3.4',
)
