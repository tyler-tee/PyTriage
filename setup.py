from setuptools import setup
from os import path

cur_directory = path.abspath(path.dirname(__file__))
with open(path.join(cur_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='PyTriage',
    version='0.2.0',
    packages=['pytriage'],
    url='https://github.com/tyler-tee/pytriage',
    license='GPLv3',
    author='Tyler Talaga',
    author_email='ttalaga@wgu.edu',
    description='PyTriage is a Python library for interacting with Cofense Triage\'s v1 and v2 API\'s.',
    long_description=long_description,
    long_description_content_type='text/markdown'
)
