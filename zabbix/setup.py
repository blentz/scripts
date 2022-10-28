#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Zabbix API
"""
import os
from setuptools import setup, find_packages, findall


def read_descr(fname):
    filepath = os.path.join(os.path.dirname(__file__), fname)
    try:
        import pypandoc
        long_description = pypandoc.convert_file(filepath, 'rst')
    except(IOError, ImportError):
        long_description = open(filepath).read()

    return long_description


setup(
    name='zabbix-api',
    url='https://github.com/gescheit/scripts',
    version='0.5.5',
    license='GNU LGPL 2.1',
    author='Aleksandr Balezin',
    author_email='gescheit12@gmail.com',
    description='Zabbix API',
    long_description=read_descr('README.md'),
    py_modules=['zabbix_api'],
    include_package_data=True,
    zip_safe=False,
    platforms='any',
    classifiers=[
         'Programming Language :: Python',
         'Programming Language :: Python :: 2',
         'Programming Language :: Python :: 3',
         'Development Status :: 5 - Production/Stable',
        ]
)
