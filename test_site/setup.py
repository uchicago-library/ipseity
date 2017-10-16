from setuptools import setup

setup(
    name="login_demo",
    py_modules=['login_demo'],
    install_requires=[
        'flask>0',
        'PyJWT',
        'flask_wtf',
        'requests'
    ]
)
