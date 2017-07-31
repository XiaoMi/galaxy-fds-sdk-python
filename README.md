
## 简介

Galaxy FDS SDK Python封装了FDS的API，用户安装SDK后，可以非常容易地调用FDS提供的接口。

## 安装

安装`pyhon-pip`后，执行`pip install galaxy-fds-sdk`即可。

也可以在requirements.txt中写上`galaxy-fds-sdk>=1.2.10`。

## 使用

使用前需要在小米开放平台注册得到应用的AccessKey和SecretKey。

### 创建Bucket

```
from fds import GalaxyFDSClient, GalaxyFDSClientException
client = GalaxyFDSClient("ACCESS_KEY", "SECRET_KEY")

try:
  client.create_bucket("bucket_name")
except GalaxyFDSClientException as e:
  print e.message
```

### 上传Object

```
client.put_object("bucket_name", "object_name", "value")
```

### 下载Object

```
client.get_object("bucket_name", "object_name")
```

### 删除Object

```
client.delete_object("bucket_name", "object_name")
```

### 删除Bucket

```
try:
  client.delete_bucket("bucket_name")
except GalaxyFDSClientException as e:
  print e.message
```

### 其他

更多API操作请参考示例代码、单元测试代码和文档。

## 实现

### HTTP请求

FDS服务端可以响应带签名认证的HTTP请求，我们使用了[requests](https://github.com/kennethreitz/requests)库发送和接收请求。相比原生的`urllib`和`urllib2`，使用`requests`后代码更加高效和易读，这是相当成熟的类库，连AWS的Python SDK也是基于它来开发的。

### 签名

我们基于`requests`的[AuthBase](http://docs.python-requests.org/en/latest/user/authentication/)实现了FDS的签名认证算法。算法实现请参考FDS官方文档。

## API

通过阅读FDS的API文档，我们实现了上传下载Object等接口。HTTP请求参数、Header等信息参见FDS官方文档。

### 参考资料

* [Python-requests-aws](https://github.com/tax/python-requests-aws)
* [Requests stream upload](http://docs.python-requests.org/en/latest/user/advanced/#streaming-requests)
* [Requests stream get](http://docs.python-requests.org/en/latest/api/#requests.Response.iter_lines)
