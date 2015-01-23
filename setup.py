try:
  from setuptools import setup
  setup()
except ImportError:
  from distutils.core import setup

setup(
  name='galaxy-fds-sdk',
  version='1.0.2',
  author='haxiaolin',
  author_email='haxiaolin@xiaomi.com',
  include_package_data=True,
  install_requires=['requests>=1.4.3'],
  license='Apache License',
  packages=['fds', 'fds.auth', 'fds.auth.signature', 'fds.model'],
  description='Galaxy FDS SDK'
)
