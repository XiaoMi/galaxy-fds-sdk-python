
[![PyPi version](https://pypip.in/v/galaxy-fds-sdk/badge.png)](https://pypi.python.org/pypi/galaxy-fds-sdk) [![PyPi downloads](https://pypip.in/d/galaxy-fds-sdk/badge.png)](https://pypi.python.org/pypi/galaxy-fds-sdk)

## Introduction

Galaxy-fds-sdk-python provides easy-to-use APIs to access FDS.

## Install

If `pyhon-pip` is installed, just need to `pip install galaxy-fds-sdk`.

You can add `galaxy-fds-sdk>=1.0` in requirements.txt.

## Usage

Before using galaxy-fds-sdk-python, you need to apply for access key and secret key in Xiaomi Open Platform.

### Create Bucket

```
import fds.GalaxyFDSClient
client = GalaxyFDSClient("your_access_key", "your_access_secret")

try:
  client.create_bucket("bucket_name")
except GalaxyFDSClientException as e:
  print e.message
```

### Upload Object

```
client.put_object("bucket_name", "object_name", "value")
```

### Download Object

```
client.get_object("bucket_name", "object_name")
```

### Delete Object

```
client.delete_object("bucket_name", "object_name")
```

### Delete Bucket

```
try:
  client.delete_bucket("bucket_name")
except GalaxyFDSClientException as e:
  print e.message
```

### Other Operations

For more usages, please refer to FDS documents and examples.

## Implement

### HTTP Requests

FDS server only accepts requests with authentication signature. So we use [requests](https://github.com/kennethreitz/requests) to send HTTP requests. Compared with `urllib` and `urllib2`, using `requests` is much more efficient.

### Signature

We implement `requests` [AuthBase](http://docs.python-requests.org/en/latest/user/authentication/) with FDS signature algorithm.

## API

We implement all the API with FDS documents. The details can be refer to official documents.

## Reference

* [Python-requests-aws](https://github.com/tax/python-requests-aws)
* [Requests stream upload](http://docs.python-requests.org/en/latest/user/advanced/#streaming-requests)
* [Requests stream get](http://docs.python-requests.org/en/latest/api/#requests.Response.iter_lines)
