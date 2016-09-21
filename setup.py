from setuptools import setup, find_packages

setup(
  name='galaxy-fds-sdk',
  version='1.1.5',
  url='https://github.com/XiaoMi/galaxy-fds-sdk-python',
  author='haxiaolin',
  author_email='haxiaolin@xiaomi.com',
  include_package_data=True,
  install_requires=['requests>=2.6.0'],
  license='Apache License',
  packages=['fds', 'fds.auth', 'fds.auth.signature', 'fds.model'],
  description='Galaxy FDS SDK'
)
