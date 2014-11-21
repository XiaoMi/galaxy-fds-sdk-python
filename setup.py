# -*- coding: utf-8 -*-
import os
import sys

try:
  from setuptools import setup
  # hush pyflakes
  setup
except ImportError:
  from distutils.core import setup


setup(
  name='galaxy-fds-sdk',
  version='1.0.5',
  author='haxiaolin',
  author_email='haxiaolin@xiaomi.com',
  include_package_data=True,
  install_requires = ['requests>=1.4.3'],
  #url='https://github.com/',
  license='Apache License',
  packages=['fds', 'fds.auth', 'fds.auth.signature', 'fds.model'],
  description='Galaxy FDS SDK',
  #long_description=open('README.md').read(),
)
