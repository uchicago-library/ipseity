from setuptools import setup

setup(
    name="login_demo",
    py_modules=['login_demo'],
    install_requires=[
        'flask>0',
        'flask_wtf',
        'flask_session',
        'pymongo',
        'cryptography',
        'PyJWT',
        'flask_jwtlib',
        'requests'
    ]
)
