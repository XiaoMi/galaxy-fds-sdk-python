from setuptools import setup

setup(
  name='galaxy-fds-sdk',
  version='1.3.3',
  author='haxiaolin',
  author_email='haxiaolin@xiaomi.com',
  include_package_data=True,
  install_requires=['requests>=2.6.0', 'argcomplete>=1.4.1'],
  license='Apache License',
  packages=['fds', 'fds.auth', 'fds.auth.signature', 'fds.model'],
  description='Galaxy FDS SDK',
  entry_points={
    'console_scripts': [
      'fds=fds.fds_cmd:main'
    ]
  }
)
