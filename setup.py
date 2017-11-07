from setuptools import setup, find_packages


def readme():
    with open("README.md", 'r') as f:
        return f.read()


setup(
    name="ipseity",
    description="An authentication API",
    version="0.2.0",
    long_description=readme(),
    author="Brian Balsamo",
    author_email="brian@brianbalsamo.com",
    packages=find_packages(
        exclude=[
        ]
    ),
    include_package_data=True,
    url='https://github.com/bnbalsamo/ipseity',
    install_requires=[
        'cryptography',
        'flask>0',
        'flask_env',
        'flask_restful',
        'flask_jwtlib',
        'PyJWT',
        'bcrypt',
        'pymongo'
    ],
    tests_require=[
        'pytest'
    ],
    test_suite='tests'
)
