import setuptools

with open('README.md', 'r') as desc:
    long_desc = desc.read()

reqs = []
with open('requirements.txt', 'r') as req:
    reqs.append(req.read())

setuptools.setup(
        name = 'ActiveDirectoryEnum',
        version = '0.5.0',
        author = 'Casper G. Nielsen',
        author_email = 'whopsec@protonmail.com',
        description = 'Enumerate Active Directory with standard vectors',
        long_description = long_desc,
        long_description_content_type = 'text/markdown',
        url = 'https://github.com/CasperGN/ActiveDirectoryEnumeration',
        packages = setuptools.find_packages(),
        install_requires = reqs, 
        include_package_data = True,
        classifiers = [
            'Programming Language :: Python :: 3',
            'License :: OSI Approved :: MIT License',
            'Environment :: Console'
        ],
        keywords='active-directory pentesting enumeration',
        python_requires = '>=3.4',
)