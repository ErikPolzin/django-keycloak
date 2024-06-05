import os

from setuptools import setup, find_packages

VERSION = '0.0.1-dev'

with open(os.path.join(os.path.dirname(__file__), 'README.md'), "r", encoding="utf-8") as readme:
    README = readme.read()

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setup(
    name='django-keycloak',
    version=VERSION,
    long_description=README,
    package_dir={'': 'src'},
    packages=find_packages('src'),
    extras_require={
        'doc': [
            'Sphinx==1.4.4',
            'sphinx-autobuild==0.6.0',
        ]
    },
    setup_requires=[
        'pytest-runner',
        'python-keycloak',
    ],
    install_requires=[
        'python-keycloak>=4.0.0',
        'djangorestframework>3.0.0',
        'Django>=5.0.0',
    ],
    tests_require=[
        'pytest-django',
        'pytest-cov',
        'mock>=2.0',
        'factory-boy',
        'freezegun'
    ],
    url='https://github.com/ErikPolzin/django-keycloak',
    license='MIT',
    author='Erik Polzin',
    author_email='eriktpol@gmail.com',
    description='Install Django Keycloak.',
    classifiers=[]
)
