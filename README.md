
## 简介

Galaxy FDS SDK Python封装了FDS的API，用户安装SDK后，可以非常容易地调用FDS提供的接口。

## 开发者
本项目采用Python官方推荐的以来管理工具`pipenv`来管理，`pipenv`作用类似于`maven`，主要依赖`Pipfile`和`Pipfile.lock`两个文件。

开发者开发步骤：
1. cd ${galaxy-fds-sdk-python}，到工程目录
2. pipenv install，安装依赖
3. pipenv install ${dependency}，例如:pipenv install flask安装依赖
4. pipenv shell，进入激活当前工程以来的python环境
5. pipenv --py，获取当前工程的python路径，此路径可以设置到vscode, pycharm等工具之中。

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

## 命令行工具
fds提供两种命令行工具：高层的`fdscli`和底层的`fds`。

`fdscli`命令行提供与aws s3类似的交互方式，主要是`rb`, `mb`, `rm`, `ls`, `cp`, `mv`, `sync(暂未实现)` 七个子命令。用户可以通过`fdscli`命令获取所有子命令名称，同时可以通过`fdscli`+子命令名称的方式，获取每个子命令具体使用方式.
```
>>> fdscli
Type:        FDS
String form: <fds.fds_cli.FDS object at 0x7fb25e4da860>
Docstring:   Advanced fds cli you deserved

Usage:       fdscli 
             fdscli cp
             fdscli ls
             fdscli mb
             fdscli mv
             fdscli rb
             fdscli rm
             fdscli sync
```

```
>>> fdscli rb
Fire trace:
1. Initial component
2. Instantiated class "FDS" (/home/hujianxin/.local/share/virtualenvs/galaxy-fds-sdk-python-uDV3PPMF/lib/python3.5/site-packages/fds/fdscli_cli.py:36)
3. Accessed property "rb" (/home/hujianxin/.local/share/virtualenvs/galaxy-fds-sdk-python-uDV3PPMF/lib/python3.5/site-packages/fds/fdscli_cli.py:96)
4. ('The function received no value for the required argument:', 'bucket_uri')

Type:        method
String form: <bound method FDS.rb of <fds.fdscli_cli.FDS object at 0x7fb7efe48940>>
File:        /home/hujianxin/.local/share/virtualenvs/galaxy-fds-sdk-python-uDV3PPMF/lib/python3.5/site-packages/fds/fdscli_cli.py
Line:        96

Usage:       fdscli rb BUCKET_URI [FORCE]
             fdscli rb --bucket-uri BUCKET_URI [--force FORCE]
```

**IMPORTANT**: 在`fdscli`命令中，通过`fds://`开头表示FDS远程资源，例如`fds://bucket_name/home/a.txt`则表示，bucket name为`bucket_name`， object name是`home/a.txt`的资源。
在cp命令中，通过 `fdscli cp a.txt fds://bucket_name/home/` 命令实现文件上传，通过`fdscli cp fds://bucket_name/home/a.txt a.txt`实现文件下载，通过`fdscli cp fds://bucket_name/home/a.txt fds://bucket_name/home/b.txt`实现CopyObject。

`fds`命令使用方式可以通过`fds`命令获取帮助

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
