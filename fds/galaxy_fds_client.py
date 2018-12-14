import hashlib
import json
from sys import version_info

IS_PY3 = version_info[0] >= 3

if IS_PY3:
  from urllib.parse import quote
else:
  from urllib import quote as _quote
  def quote(x):
    if isinstance(x, unicode):
      x = x.encode('utf8')
    return _quote(x)
import requests

from fds.auth.common import Common
from fds.auth.signature.signer import Signer
from fds.fds_client_configuration import FDSClientConfiguration
from fds.fds_request import FDSRequest
from fds.galaxy_fds_client_exception import GalaxyFDSClientException
from fds.model.access_control_policy import AccessControlPolicy
from fds.model.fds_bucket import FDSBucket
from fds.model.fds_object import FDSObject
from fds.model.fds_object_listing import FDSObjectListing
from fds.model.fds_object_metadata import FDSObjectMetadata
from fds.model.fds_object_summary import FDSObjectSummary
from fds.model.permission import AccessControlList, UserGroups, Permission, \
  GrantType
from fds.model.permission import Grant
from fds.model.permission import Grantee
from fds.model.permission import Owner
from fds.model.put_object_result import PutObjectResult
from fds.model.subresource import SubResource
from fds.model.init_multipart_upload_result import InitMultipartUploadResult
from fds.model.upload_part_result import UploadPartResult
from fds.model.fds_lifecycle import FDSLifecycleConfig, FDSLifecycleRule
from fds.model.copy_object_result import CopyObjectResult
from fds.model.timestamp_anti_stealing_link_config import TimestampAntiStealingLinkConfig
import os
import sys
from .utils import uri_to_bucket_and_object, to_json_object
import logging

from fds.model.upload_part_result_list import UploadPartResultList
from io import BytesIO
from io import IOBase
from io import StringIO
from time import sleep


class GalaxyFDSClient(object):
  '''
  Client for Galaxy FDS Service.
  '''

  def __init__(self, access_key=None, access_secret=None, config=None):
    '''
    :param access_key:    The app access key
    :param access_secret: The app access secret
    :param config:        The FDS service's config
    '''
    self._delimiter = "/"

    if access_key == None or access_secret == None:
      self._access_key = self.load_access_key()
      self._secret_key = self.load_secret_key()
    else:
      self._access_key = access_key
      self._secret_key = access_secret

    self._auth = Signer(self._access_key, self._secret_key)
    if config == None:
      config = FDSClientConfiguration()
      config.set_endpoint(self.load_endpoint())

    self._config = config
    self._request = FDSRequest(config.timeout, config.max_retries)

  def load_endpoint(self):
    endpoint = None
    if endpoint is None and "XIAOMI_FDS_ENDPOINT" in os.environ:
      endpoint = os.environ["XIAOMI_FDS_ENDPOINT"]
    if endpoint is None and "FDS_ENDPOINT" in os.environ:
      endpoint = os.environ["FDS_ENDPOINT"]
    if endpoint is None:
      endpoint = self.load_config("xiaomi_fds_endpoint")
    if endpoint is not None and len(endpoint.strip()) == 0:
      logging.warn(
        "endpoint is set to empty, please check ${XIAOMI_FDS_ENDPOINT} or ${FDS_ENDPOINT} in environ variables, or \"xiaomi_fds_endpoint\" in ~/.config/xiaomi/config")
    return endpoint

  def load_access_key(self):
    access_key = None
    if access_key is None and "XIAOMI_ACCESS_KEY_ID" in os.environ:
      access_key = os.environ["XIAOMI_ACCESS_KEY_ID"]
    if access_key is None and "XIAOMI_ACCESS_KEY" in os.environ:
      access_key = os.environ["XIAOMI_ACCESS_KEY"]
    if access_key is None:
      access_key = self.load_config("xiaomi_access_key_id")
    if access_key is not None and len(access_key.strip()) == 0:
      logging.warn(
        "access_key is set to empty, please check ${XIAOMI_ACCESS_KEY_ID} or ${XIAOMI_ACCESS_KEY} in environ variables, or \"xiaomi_access_key_id\" in ~/.config/xiaomi/config")
    return access_key

  def load_secret_key(self):
    secret_key = None
    if secret_key is None and "XIAOMI_SECRET_ACCESS_KEY" in os.environ:
      secret_key = os.environ["XIAOMI_SECRET_ACCESS_KEY"]
    if secret_key is None and "XIAOMI_SECRET_KEY" in os.environ:
      secret_key = os.environ["XIAOMI_SECRET_KEY"]
    if secret_key is None:
      secret_key = self.load_config("xiaomi_secret_access_key")
    if secret_key is not None and len(secret_key.strip()) == 0:
      logging.warn(
        "secret_key is set to empty, please check ${XIAOMI_SECRET_ACCESS_KEY} or ${XIAOMI_SECRET_KEY} in environ variables, or \"xiaomi_secret_access_key\" in ~/.config/xiaomi/config")
    return secret_key

  def load_config(self, config_key):
    try:
      config_filename = os.path.join(os.path.expanduser('~'), ".config/xiaomi/config")
      if os.path.exists(config_filename):
        with open(config_filename) as f:
          data = to_json_object(f.read())
          return data[config_key]
    except:
      pass

  @property
  def delimiter(self):
    return self._delimiter

  @delimiter.setter
  def delimiter(self, delimiter):
    self._delimiter = delimiter

  def does_bucket_exist(self, bucket_name):
    '''
    Check the existence of a specified bucket.
    :param bucket_name: The bucket name of the bucket to check
    :return: True if the bucket exists, otherwise False
    '''
    uri = '%s%s' % (self._config.get_base_uri(), quote(bucket_name))
    response = self._request.head(uri, auth=self._auth)
    if response.status_code == requests.codes.ok:
      return True
    elif response.status_code == requests.codes.not_found:
      return False
    else:
      headers = ""
      if self._config.debug:
        headers = ' header=%s' % response.headers
      message = 'Check bucket existence failed, status=%s, reason=%s%s' % (
        response.status_code, response.content, headers)
      raise GalaxyFDSClientException(message)

  def list_buckets(self):
    '''
    List all the buckets of the current developer.
    :return: A list of FDSBucket which contains name and owner of the bucket.
    '''
    uri = self._config.get_base_uri()
    response = self._request.get(uri, auth=self._auth)
    if response.status_code != requests.codes.ok:
      headers = ""
      if self._config.debug:
        headers = ' header=%s' % response.headers
      message = 'List buckets failed, status=%s, reason=%s%s' % (
        response.status_code, response.content, headers)
      raise GalaxyFDSClientException(message)
    elif response.content:
      buckets_list = []
      json_response = to_json_object(response.content)
      buckets = json_response['buckets']
      owner = Owner().from_json(json_response['owner'])
      for bucket in buckets:
        buckets_list.append(FDSBucket(bucket['name'], owner))
      return buckets_list
    else:
      return list()

  def list_authorized_buckets(self):
    '''
    List all the authorized buckets of the current developer.
    :return: A list of FDSBucket which contains name and owner of the bucket.
    '''
    uri = self._config.get_base_uri()
    response = self._request.get(uri, auth=self._auth, params={"authorizedBuckets": "true"})
    if response.status_code != requests.codes.ok:
      headers = ""
      if self._config.debug:
        headers = ' header=%s' % response.headers
      message = 'List buckets failed, status=%s, reason=%s%s' % (
        response.status_code, response.content, headers)
      raise GalaxyFDSClientException(message)
    elif response.content:
      buckets_list = []
      json_response = to_json_object(response.content)
      buckets = json_response['buckets']
      for bucket in buckets:
        buckets_list.append(FDSBucket(bucket['name'], ''))
      return buckets_list
    else:
      return list()

  def create_bucket(self, bucket_name):
    '''
    Create a bucket with the specified name.
    :param bucket_name: The name of the bucket to create
    '''
    uri = '%s%s' % (self._config.get_base_uri(), quote(bucket_name))
    response = self._request.put(uri, auth=self._auth)
    if response.status_code != requests.codes.ok:
      headers = ""
      if self._config.debug:
        headers = ' header=%s' % response.headers
      message = 'Create bucket failed, status=%s, reason=%s%s' % (
        response.status_code, response.content, headers)
      raise GalaxyFDSClientException(message)

  def delete_bucket(self, bucket_name):
    '''
    Delete a bucket of a specified name.
    :param bucket_name: The name of the bucket to delete
    '''
    uri = '%s%s' % (self._config.get_base_uri(), quote(bucket_name))
    response = self._request.delete(uri, auth=self._auth)
    if (response.status_code != requests.codes.ok and
        response.status_code != requests.codes.not_found):
      headers = ""
      if self._config.debug:
        headers = ' header=%s' % response.headers
      message = 'Delete bucket failed, status=%s, reason=%s%s' % (
        response.status_code, response.content, headers)
      raise GalaxyFDSClientException(message)

  def list_objects(self, bucket_name, prefix='', delimiter=None, max_keys=None):
    '''
    List all objects in a specified bucket with prefix. If the number of objects
    in the bucket is larger than a threshold, you would get a FDSObjectListing
    contains no FDSObjects. In this scenario, you should call
    list_next_batch_of_objects with the returned value
    :param bucket_name: The name of the bucket to whom the object is put
    :param prefix:      The prefix of the object to list
    :param delimiter:   The delimiter used in listing, using '/' if 'None' given
    :return:  FDSObjectListing contains FDSObject list and other metadata
    '''
    if delimiter is None:
      delimiter = self._delimiter
    uri = '%s%s' % (self._config.get_base_uri(), quote(bucket_name))
    params = {
      'prefix': prefix,
      'delimiter': delimiter
    }
    if max_keys is not None:
      params["maxKeys"] = str(max_keys)
    response = self._request.get(uri, auth=self._auth, params=params)
    if response.status_code == requests.codes.ok:
      objects_list = FDSObjectListing(to_json_object(response.content))
      return objects_list
    else:
      headers = ""
      if self._config.debug:
        headers = ' header=%s' % response.headers
      message = 'List objects under bucket %s with prefix %s failed, ' \
                'status=%s, reason=%s%s' % \
                (bucket_name, prefix, response.status_code, response.content, headers)
      raise GalaxyFDSClientException(message)

  def list_trash_objects(self, prefix='', delimiter=None, max_keys=None):
    '''
    Compared with list_objects, it returns a list of objects in the trash.
    :param prefix: The prefix of bucket_name/object_name.
    :param delimiter: The delimiter used in listing, using '/' if 'None' given.
    :return: FDSObjectListing contains a list of objects in the trash.
    '''
    return self.list_objects("trash", prefix, delimiter, max_keys=max_keys);

  def list_next_batch_of_objects(self, previous):
    '''
    List objects in a iterative manner
    :param previous: The FDSObjectListing returned by previous call or list_objects
    :return:  FDSObjectListing contains FDSObject list and other metadata, 'None'
              if all objects returned by previous calls
    '''
    if not previous.is_truncated:
      return None
    bucket_name = previous.bucket_name
    prefix = previous.prefix
    delimiter = previous.delimiter
    marker = previous.next_marker
    uri = "%s%s" % (self._config.get_base_uri(), quote(bucket_name))
    response = self._request.get(uri, auth=self._auth, params={
      'prefix': previous.prefix,
      'delimiter': previous.delimiter,
      'marker': previous.next_marker,
      'maxKeys': previous.max_keys
    })
    if response.status_code == requests.codes.ok:
      objects_list = FDSObjectListing(to_json_object(response.content))
      return objects_list
    else:
      headers = ""
      if self._config.debug:
        headers = ' header=%s' % response.headers
      message = 'List next batch of objects under bucket %s with prefix %s ' \
                'and marker %s failed, status=%s, reason=%s%s' % \
                (bucket_name, prefix, marker, response.status_code, response.content,
                 headers)
      raise GalaxyFDSClientException(message)

  def put_object_with_uri(self, uri, data, metadata=None):
    '''
    Put the object with the uri.
    :param uri:         The uri of th bucket and object
    :param data:        The data to put, bytes or a file like object
    :param metadata:    The metadata of the object
    :return: The result of putting action server returns
    '''
    bucket_name, object_name = uri_to_bucket_and_object(uri)
    self.put_object(bucket_name, object_name, data, metadata)

  def put_object(self, bucket_name, object_name, data, metadata=None):
    '''
    Put the object to a specified bucket. If a object with the same name already
    existed, it will be overwritten.
    :param bucket_name: The name of the bucket to whom the object is put
    :param object_name: The name of the object to put
    :param data:        The data to put, bytes or a file like object
    :param metadata:    The metadata of the object
    :return: The result of putting action server returns
    '''
    part_size = self._config.get_part_size()
    threshold_size = self._config.get_threshold_size()
    inputstream = None

    if isinstance(data, bytes):
      inputstream = BytesIO(data)
    elif isinstance(data, str):
      inputstream = StringIO(data)
    elif not IS_PY3 and isinstance(data, file):
      inputstream = data
    elif (isinstance(data, IOBase)):
      if data.seekable():
        inputstream = data
      else:
        buf = data.readlines()
        if len(buf) > 0:
          if isinstance(buf[0], str):
            inputstream = StringIO(''.join(buf))
          else:
            inputstream = BytesIO(b''.join(buf))
        else:
          inputstream = StringIO('')
    else:
      raise GalaxyFDSClientException("Cannot identify data type")

    pos = inputstream.tell()
    inputstream.seek(0, 2)
    filen = inputstream.tell()
    inputstream.seek(0, pos)
    if filen < threshold_size:
      return self.put_object_directly(bucket_name, object_name, inputstream, metadata)
    else:
      content = inputstream.read(part_size)
      upload_token = self.init_multipart_upload(bucket_name, object_name)
      upload_list = []
      part_number = 1
      while (content):

        upload_result = None
        for i in range(3):
          try:
            upload_result = self.upload_part(bucket_name, object_name, upload_token.upload_id,
                                             part_number, content)
            upload_list.append(upload_result)
            break
          except:
            logging.warning("upload part %d failed, retry after %d seconds" % (part_number, 3))
            sleep(3)

        part_number = part_number + 1
        content = inputstream.read(part_size)
      upload_part_result = UploadPartResultList({"uploadPartResultList": upload_list})
      return self.complete_multipart_upload(bucket_name=bucket_name, object_name=object_name,
                                            upload_id=upload_token.upload_id,
                                            metadata=metadata,
                                            upload_part_result_list=json.dumps(upload_part_result))

  def put_object_directly(self, bucket_name, object_name, data, metadata=None):
    '''
    Put the object to a specified bucket. If a object with the same name already
    existed, it will be overwritten.
    :param bucket_name: The name of the bucket to whom the object is put
    :param object_name: The name of the object to put
    :param data:        The data to put, bytes or a file like object
    :param metadata:    The metadata of the object
    :return: The result of putting action server returns
    '''
    uri = '%s%s/%s' % (self._config.get_upload_base_uri(), quote(bucket_name), quote(object_name))
    if metadata is None:
      metadata = FDSObjectMetadata()
    inputstream = None
    if isinstance(data, bytes):
      inputstream = BytesIO(data)
    elif isinstance(data, str):
      inputstream = StringIO(data)
    elif not IS_PY3 and isinstance(data, file):
      inputstream = data
    elif (isinstance(data, IOBase)):
      if data.seekable():
        inputstream = data
      else:
        buf = data.readlines()
        if len(buf) > 0:
          if isinstance(buf[0], str):
            inputstream = StringIO(''.join(buf))
          else:
            inputstream = BytesIO(b''.join(buf))
        else:
          inputstream = StringIO('')
    else:
      raise GalaxyFDSClientException("Cannot identify data type")

    if self._config.enable_md5_calculate:
      digest = hashlib.md5()
      pos = inputstream.tell()
      content = inputstream.read()
      if IS_PY3 and isinstance(content, str):
        content = content.encode(encoding="UTF-8")
      digest.update(content)
      inputstream.seek(0, pos)

      metadata.add_header(Common.CONTENT_MD5, digest.hexdigest())
    response = None
    if IS_PY3 and isinstance(inputstream, StringIO):
      response = self._request.put(uri, data=inputstream.read(), auth=self._auth,
                                   headers=metadata.metadata)
    else:
      response = self._request.put(uri, data=inputstream, auth=self._auth,
                                   headers=metadata.metadata)
    if response.status_code == requests.codes.ok:
      return PutObjectResult(to_json_object(response.content))
    headers = ""
    if self._config.debug:
      headers = ' header=%s' % response.headers
    message = 'Put object failed, status=%s, reason=%s%s' % (
      response.status_code, response.content, headers)
    raise GalaxyFDSClientException(message)

  def post_object(self, bucket_name, data, metadata=None):
    '''
    Post the object to a specified bucket. The object name will be generated
    by the server uniquely.
    :param bucket_name: The name of the bucket to whom the object is put
    :param data:        The data to put, bytes or a file like object
    :param metadata:    The metadata of the object
    :return: The result of posting action server returns
    '''
    uri = '%s%s/' % (self._config.get_upload_base_uri(), quote(bucket_name))
    if metadata is None:
      metadata = FDSObjectMetadata()
    if self._config.enable_md5_calculate:
      digest = hashlib.md5()
      digest.update(data)
      metadata.add_header(Common.CONTENT_MD5, digest.hexdigest())

    response = self._request.post(uri, data=data, auth=self._auth,
                                  headers=metadata.metadata)
    if response.status_code == requests.codes.ok:
      return PutObjectResult(to_json_object(response.content))
    headers = ""
    if self._config.debug:
      headers = ' header=%s' % response.headers
    message = 'Post object failed, status=%s, reason=%s%s' % (
      response.status_code, response.content, headers)
    raise GalaxyFDSClientException(message)

  def get_object_with_uri(self, uri, position=0, size=4096):
    '''
    Get a specified object from fds uri.
    :param uri:         The uri of th bucket and object
    :param position:    The start index of object to get
    :param size:        The maximum size of each piece when return streaming is on
    :return:            The FDS object
    '''
    bucket_name, object_name = uri_to_bucket_and_object(uri)
    return self.get_object(bucket_name, object_name, position, size)

  def get_object(self, bucket_name, object_name, position=0, size=4096, stream=None,
                 version_id=None):
    '''
    Get a specified object from a bucket.
    :param bucket_name: The name of the bucket from whom to get the object
    :param object_name: The name of the object to get
    :param position: The start index of object to get
    :param size:        The maximum size of each piece when return streaming is on
    :param stream:      Set True to enable streaming, otherwise, whole object content is read to memory
    :return: The FDS object
    '''
    if position < 0:
      raise GalaxyFDSClientException("Seek position should be no less than 0")
    uri = '%s%s/%s' % (self._config.get_download_base_uri(), quote(bucket_name), quote(object_name))
    req_params = dict()
    if version_id:
      req_params["versionId"] = version_id

    if position > 0:
      header = {Common.RANGE: 'bytes=%d-' % position}
      response = self._request.get(uri, auth=self._auth, headers=header, stream=stream,
                                   params=req_params)
    else:
      response = self._request.get(uri, auth=self._auth, stream=stream, params=req_params)
    if response.status_code == requests.codes.ok or \
        response.status_code == requests.codes.partial:
      obj = FDSObject()
      obj.stream = response.iter_content(chunk_size=size)
      summary = FDSObjectSummary()
      summary.bucket_name = bucket_name
      summary.object_name = object_name
      summary.size = int(response.headers['content-length'])
      obj.summary = summary
      obj.metadata = self._parse_object_metadata_from_headers(response.headers)
      return obj
    else:
      headers = ""
      if self._config.debug:
        headers = ' header=%s' % response.headers
      message = 'Get object failed, status=%s, reason=%s%s' % (
        response.status_code, response.content, headers)
      raise GalaxyFDSClientException(message)

  def download_object_with_uri(self, uri, data_file, offset=0, length=-1):
    bucket_name, object_name = uri_to_bucket_and_object(uri)
    self.download_object(bucket_name, object_name, data_file, offset, length)

  def download_object(self, bucket_name, object_name, data_file, offset=0, length=-1):
    fds_object = self.get_object(bucket_name=bucket_name,
                                 object_name=object_name,
                                 position=offset)
    length_left = length
    if length_left == -1:
      length_left = IS_PY3 and sys.maxsize or sys.maxint
    try:
      if data_file:
        with open(data_file, "wb") as f:
          for chunk in fds_object.stream:
            l = min(length_left, len(chunk));
            f.write(chunk[0:l])
            length_left -= l
            if length_left <= 0:
              break
      else:
        for chunk in fds_object.stream:
          l = min(length_left, len(chunk))
          if IS_PY3:
            sys.stdout.buffer.write(chunk[0:l])
          else:
            sys.stdout.write(chunk[0:l])
          length_left -= l
          if length_left <= 0:
            break
        sys.stdout.flush()
    finally:
      fds_object.stream.close()

  def does_object_exists(self, bucket_name, object_name):
    '''
    Check the existence of a specified object.
    :param bucket_name: The name of the bucket
    :param object_name: The name of the object to check
    :return: True if the object exists, otherwise, False
    '''
    uri = '%s%s/%s' % (self._config.get_base_uri(), quote(bucket_name), quote(object_name))
    response = self._request.head(uri, auth=self._auth)
    if response.status_code == requests.codes.ok:
      return True
    elif response.status_code == requests.codes.not_found:
      return False
    else:
      headers = ""
      if self._config.debug:
        headers = ' header=%s' % response.headers
      message = 'Check object existence failed, status=%s, reason=%s%s' % (
        response.status_code, response.content, headers)
      raise GalaxyFDSClientException(message)

  def delete_object(self, bucket_name, object_name, **kwargs):
    '''
    Delete specified object.
    :param bucket_name: The name of the bucket
    :param object_name: The name of the object
    '''
    uri = '%s%s/%s' % (self._config.get_base_uri(), quote(bucket_name), quote(object_name))
    params = {}
    if "enable_trash" in kwargs and kwargs["enable_trash"] is False:
      params["enableTrash"] = "false"

    response = self._request.delete(uri, auth=self._auth, params=params)
    if response.status_code != requests.codes.ok:
      headers = ""
      if self._config.debug:
        headers = ' header=%s' % response.headers
      message = 'Delete object failed, status=%s, reason=%s%s' % (
        response.status_code, response.content, headers)
      raise GalaxyFDSClientException(message)

    if "object-version-id" in response.headers:
      return response.headers["object-version-id"]
    return None

  def delete_objects(self, bucket_name, object_names):
    '''
    Delete specified objects in the bucket
    :param bucket_name:
    :param object_names:
    :return:
    '''
    uri = "%s%s" % (self._config.get_base_uri(), quote(bucket_name))
    response = self._request.put(uri, auth=self._auth, data=json.dumps(object_names), params={"deleteObjects": "true"})
    if response.status_code != requests.codes.ok:
      headers = ""
      if self._config.debug:
        headers = ' header=%s' % response.headers
      message = 'Restore object failed, status=%s, reason=%s%s' % (
        response.status_code, response.content, headers)
      raise GalaxyFDSClientException(message)
    else:
      failed_list = to_json_object(response.content)
      return failed_list

  def restore_object(self, bucket_name, object_name):
    '''
    Restore a specified object from trash.
    :param bucket_name:     The name of the bucket
    :param object_name: The name of the object
    '''
    uri = '%s%s/%s' % (self._config.get_base_uri(), quote(bucket_name), quote(object_name))
    response = self._request.put(uri, auth=self._auth, params={"restore": 'true'})
    if response.status_code != requests.codes.ok:
      headers = ""
      if self._config.debug:
        headers = ' header=%s' % response.headers
      message = 'Restore object failed, status=%s, reason=%s%s' % (
        response.status_code, response.content, headers)
      raise GalaxyFDSClientException(message)

  def rename_object(self, bucket_name, src_object_name, dst_object_name):
    '''
    Rename a specified object to a new name.
    :param bucket_name:     The name of the bucket
    :param src_object_name: The original name of the object
    :param dst_object_name: The target name of the object to rename to
    '''
    uri = '%s%s/%s' % (self._config.get_base_uri(), quote(bucket_name), quote(src_object_name))
    response = self._request.put(uri, auth=self._auth, params={"renameTo": dst_object_name})
    if response.status_code != requests.codes.ok:
      headers = ""
      if self._config.debug:
        headers = ' header=%s' % response.headers
      message = 'Rename object failed, status=%s, reason=%s%s' % (
        response.status_code, response.content, headers)
      raise GalaxyFDSClientException(message)

  def set_bucket_acl(self, bucket_name, acl):
    '''
    Add grant(ACL) for specified bucket.
    :param bucket_name: The name of the bucket to add grant
    :param acl:         The grant(ACL) to add
    '''
    uri = '%s%s' % (self._config.get_base_uri(), quote(bucket_name))
    acp = self._acl_to_acp(acl)
    response = self._request.put(uri, auth=self._auth,
                                 params={SubResource.ACL: 'true'},
                                 data=json.dumps(acp, default=lambda x: x.to_string()))
    if response.status_code != requests.codes.ok:
      headers = ""
      if self._config.debug:
        headers = ' header=%s' % response.headers
      message = 'Set bucket acl failed, status=%s, reason=%s%s' % (
        response.status_code, response.content, headers)
      raise GalaxyFDSClientException(message)

  def get_bucket_acl(self, bucket_name):
    '''
    Get the ACL of a specified bucket.
    :param bucket_name: The name of the bucket to get ACL
    :return: The got access control list
    '''
    uri = '%s%s' % (self._config.get_base_uri(), quote(bucket_name))
    response = self._request.get(uri, auth=self._auth, params={SubResource.ACL: 'true'})
    if response.status_code == requests.codes.ok:
      acp = AccessControlPolicy(to_json_object(response.content))
      acl = self._acp_to_acl(acp)
      return acl
    else:
      headers = ""
      if self._config.debug:
        headers = ' header=%s' % response.headers
      message = 'Get bucket acl failed, status=%s, reason=%s%s' % (
        response.status_code, response.content, headers)
      raise GalaxyFDSClientException(message)

  def set_object_acl(self, bucket_name, object_name, acl):
    '''
    Add grant(ACL) for a specified object.
    :param bucket_name: The name of the bucket
    :param object_name: The name of the object
    :param acl:         The grant(ACL) to add
    '''
    uri = '%s%s/%s' % (self._config.get_base_uri(), quote(bucket_name), quote(object_name))
    acp = self._acl_to_acp(acl)
    response = self._request.put(uri, auth=self._auth, params={SubResource.ACL: 'true'},
                                 data=json.dumps(acp, default=lambda x: x.to_string()))
    if response.status_code != requests.codes.ok:
      headers = ""
      if self._config.debug:
        headers = ' header=%s' % response.headers
      message = 'Set object acl failed, status=%s, reason=%s%s' % (
        response.status_code, response.content, headers)
      raise GalaxyFDSClientException(message)

  def get_object_acl(self, bucket_name, object_name):
    '''
    Get the ACL of a specified object.
    :param bucket_name: The name of the bucket
    :param object_name: The name of the object
    :return: The got access control list
    '''
    uri = '%s%s/%s' % (self._config.get_base_uri(), quote(bucket_name), quote(object_name))
    response = self._request.get(uri, auth=self._auth, params={SubResource.ACL: 'true'})
    if response.status_code == requests.codes.ok:
      acp = AccessControlPolicy(to_json_object(response.content))
      acl = self._acp_to_acl(acp)
      return acl
    else:
      headers = ""
      if self._config.debug:
        headers = ' header=%s' % response.headers
      message = 'Get object acl failed, status=%s, reason=%s%s' % (
        response.status_code, response.content, headers)
      raise GalaxyFDSClientException(message)

  def get_object_metadata(self, bucket_name, object_name):
    '''
    Get the metadata of a specified object.
    :param bucket_name: The name of the bucket
    :param object_name: The name of the object
    :return: The got object metadata
    '''
    uri = '%s%s/%s' % (self._config.get_base_uri(), quote(bucket_name), quote(object_name))
    response = self._request.get(uri, auth=self._auth, params={SubResource.METADATA: 'true'})
    if response.status_code == requests.codes.ok:
      metadata = self._parse_object_metadata_from_headers(response.headers)
      return metadata
    else:
      headers = ""
      if self._config.debug:
        headers = ' header=%s' % response.headers
      message = 'Get object metadata failed, status=%s, reason=%s%s' % (
        response.status_code, response.content, headers)
      raise GalaxyFDSClientException(message)

  def prefetch_object(self, bucket_name, object_name):
    '''
    Prefetch the object to CDN
    :param bucket_name: The name of the bucket
    :param object_name: The name of the object
    :return: void
    '''
    uri = '%s%s/%s' % (self._config.get_base_uri(), quote(bucket_name), quote(object_name))
    response = self._request.put(uri, auth=self._auth, data="", params={"prefetch": 'true'})
    if response.status_code != requests.codes.ok:
      headers = ""
      if self._config.debug:
        headers = ' header=%s' % response.headers
      message = 'Prefetch object failed, status=%s, reason=%s%s' % (
        response.status_code, response.content, headers)
      raise GalaxyFDSClientException(message)

  def refresh_object(self, bucket_name, object_name):
    '''
    Refresh the cache of the object in CDN
    :param bucket_name: The name of the bucket
    :param object_name: The name of the object
    :return: void
    '''
    uri = '%s%s/%s' % (self._config.get_base_uri(), quote(bucket_name), quote(object_name))
    response = self._request.put(uri, auth=self._auth, data="", params={"refresh": 'true'})
    if response.status_code != requests.codes.ok:
      headers = ""
      if self._config.debug:
        headers = ' header=%s' % response.headers
      message = 'Refresh object failed, status=%s, reason=%s%s' % (
        response.status_code, response.content, headers)
      raise GalaxyFDSClientException(message)

  def set_public(self, bucket_name, object_name):
    acl = AccessControlList()
    grant = Grant(Grantee(UserGroups.ALL_USERS), Permission.READ)
    grant.type = GrantType.GROUP
    acl.add_grant(grant)
    self.set_object_acl(bucket_name, object_name, acl)

  def init_multipart_upload(self, bucket_name, object_name):
    '''
    Init a multipart upload session
    :param bucket_name:
    :param object_name:
    :return:
    '''
    uri = '%s%s/%s' % (self._config.get_base_uri(), quote(bucket_name), quote(object_name))
    response = self._request.put(uri, auth=self._auth, data="", params={"uploads": 'true'})
    if response.status_code == requests.codes.ok:
      result = InitMultipartUploadResult(to_json_object(response.content))
      return result
    else:
      headers = ""
      if self._config.debug:
        headers = ' headers=%s' % response.headers
      message = 'Init multipart upload failed, status=%s, reason=%s%s' % (
        response.status_code, response.content, headers)
      raise GalaxyFDSClientException(message)

  def upload_part(self, bucket_name, object_name, upload_id, part_number, data):
    '''
    Upload a multipart upload part
    :param bucket_name:
    :param object_name:
    :param upload_id:
    :param part_number:
    :param data:
    :return:
    '''
    uri = '%s%s/%s' % (self._config.get_base_uri(), quote(bucket_name), quote(object_name))
    response = self._request.put(uri, auth=self._auth, data=data, params={
      "uploadId": upload_id,
      "partNumber": str(part_number)
    })
    if response.status_code == requests.codes.ok:
      result = UploadPartResult(to_json_object(response.content))
      return result
    else:
      headers = ""
      if self._config.debug:
        headers = ' headers=%s' % response.headers
      message = 'Upload part failed, status=%s, reason=%s%s' % (
        response.status_code, response.content, headers)
      raise GalaxyFDSClientException(message)

  def complete_multipart_upload(self, bucket_name, object_name, upload_id,
                                metadata, upload_part_result_list):
    '''
    Complete a multipart upload
    :param bucket_name:
    :param object_name:
    :param upload_id:
    :param metadata:
    :param upload_part_result_list:
    :return:
    '''
    uri = '%s%s/%s' % (self._config.get_base_uri(), quote(bucket_name), quote(object_name))
    if metadata is None:
      metadata = FDSObjectMetadata()
    response = self._request.put(uri, auth=self._auth,
                                 data=upload_part_result_list, headers=metadata.metadata,
                                 params={"uploadId": upload_id})
    if response.status_code == requests.codes.ok:
      result = PutObjectResult(to_json_object(response.content))
      return result
    else:
      headers = ""
      if self._config.debug:
        headers = ' headers=%s' % response.headers
      message = 'Complete multipart upload failed, status=%s, reason=%s%s' % (
        response.status_code, response.content, headers)
      raise GalaxyFDSClientException(message)

  def abort_multipart_upload(self, bucket_name, object_name, upload_id):
    '''
    Abort a multipart upload
    :param bucket_name:
    :param object_name:
    :param upload_id:
    :return:
    '''
    uri = '%s%s/%s' % (self._config.get_base_uri(), quote(bucket_name), quote(object_name))
    response = self._request.delete(uri, auth=self._auth, data='', params={
      "uploadId": upload_id
    })
    if response.status_code != requests.codes.ok:
      headers = ""
      if self._config.debug:
        headers = ' headers=%s' % response.headers
      message = 'Abort multipart upload failed, status=%s, reason=%s%s' % (
        response.status_code, response.content, headers)
      raise GalaxyFDSClientException(message)

  def generate_presigned_uri(self, base_uri, bucket_name, object_name,
                             expiration, http_method="GET", content_type=None, sub_resources=None):
    '''
    Generate a pre-signed uri to share object with the public
    :param base_uri: The base uri of rest server. Use client's default if 'None' pass
    :param bucket_name: The name of the bucket
    :param object_name: The name of the object
    :param expiration: The expiration time of the uri: milliseconds from the Epoch
    :param http_method: The http method used in uri
    :return: The pre-signed uri string
    '''
    if not base_uri or base_uri == '':
      if http_method == 'PUT' or http_method == 'POST':
        base_uri = self._config.get_upload_base_uri()
      elif http_method == 'DELETE':
        base_uri = self._config.get_base_uri()
      else:
        base_uri = self._config.get_download_base_uri()
    if not IS_PY3 and isinstance(base_uri, unicode):
      base_uri = base_uri.encode('utf8')
    try:
      if sub_resources == None:
        uri = '%s%s/%s?%s=%s&%s=%s&' % \
              (base_uri, bucket_name, object_name, \
               Common.GALAXY_ACCESS_KEY_ID, self._auth._app_key, \
               Common.EXPIRES, str(int(expiration)))
      else:
        uri = '%s%s/%s?%s&%s=%s&%s=%s&' % \
              (base_uri, bucket_name, object_name, '&'.join(sub_resources), \
               Common.GALAXY_ACCESS_KEY_ID, self._auth._app_key, \
               Common.EXPIRES, str(int(expiration)))
      headers = None
      if content_type != None and isinstance(content_type, IS_PY3 and str or basestring):
        headers = {Common.CONTENT_TYPE: content_type}
      signature = str(self._auth._sign_to_base64(http_method, headers, uri, \
                                                 self._auth._app_secret))
      if sub_resources == None:
        return '%s%s/%s?%s=%s&%s=%s&%s=%s' % \
               (base_uri, quote(bucket_name), quote(object_name), \
                Common.GALAXY_ACCESS_KEY_ID, self._auth._app_key, \
                Common.EXPIRES, str(int(expiration)), Common.SIGNATURE, signature)
      else:
        return '%s%s/%s?%s&%s=%s&%s=%s&%s=%s' % \
               (base_uri, quote(bucket_name), quote(object_name), '&'.join(sub_resources), \
                Common.GALAXY_ACCESS_KEY_ID, self._auth._app_key, \
                Common.EXPIRES, str(int(expiration)), Common.SIGNATURE, signature)

    except Exception as e:
      import traceback
      traceback.print_exc()
      message = 'Wrong expiration given. ' \
                'Milliseconds since January 1, 1970 should be used. ' + str(e)
      raise GalaxyFDSClientException(message)

  def generate_download_object_uri(self, bucket_name, object_name):
    '''
    Generate a URI for downloading object
    '''
    return '%s%s/%s' % (self._config.get_download_base_uri(), bucket_name,
                        object_name)

  def copy_object(self, src_bucket_name, src_object_name, dst_bucket_name, dst_object_name):
    '''
    Copy src_object_name from src_bucket_name to dst_bucket_name, and rename it to dst_object_name
    :param src_bucket_name: Source bucket name
    :param src_object_name: Source object name
    :param dst_bucket_name: Target bucket name
    :param dst_object_name: Target object name
    :return:
    '''
    uri = '%s%s/%s' % (self._config.get_upload_base_uri(), quote(dst_bucket_name),\
      quote(dst_object_name))

    data = {"srcBucketName": src_bucket_name, "srcObjectName": src_object_name}

    response = self._request.put(uri, data=json.dumps(data, default=lambda x: x.to_string()),
                                 auth=self._auth, params={"cp": "cpparam"})
    if response.status_code == requests.codes.ok:
      return CopyObjectResult(to_json_object(response.content))
    headers = ""
    if self._config.debug:
      headers = ' header=%s' % response.headers
    message = 'Copy object failed, status=%s, reason=%s%s' % (
      response.status_code, response.content, headers)
    raise GalaxyFDSClientException(message)

  def _acp_to_acl(self, acp):
    '''
    Translate AccessControlPolicy to AccessControlList.
    '''
    if acp is not None:
      acl = AccessControlList()
      for item in acp['accessControlList']:
        grantee = item['grantee']
        grant_id = grantee['id']
        permission = item['permission']
        g = Grant(Grantee(grant_id), permission)
        acl.add_grant(g)
      return acl
    return str()

  # def copy_object(self, srcBucketName, srcObjectName, dstBucketName, dstObjectName):
  #   cp_request = FDSCopyObjectRequest(srcBucketName, srcObjectName, dstBucketName, dstObjectName)
  #   return self.copy_object(cp_request)

  def _acl_to_acp(self, acl):
    '''
    Translate AccessControlList to AccessControlPolicy.
    '''
    if acl is not None:
      acp = AccessControlPolicy(dict())
      owner = Owner()
      owner.id = self._access_key
      acp.owner = owner
      acp.access_control_list = acl.get_grant_list()
      return acp
    return ''

  def _parse_object_metadata_from_headers(self, response_headers):
    '''
    Parse object metadata from the response headers.
    '''
    metadata = FDSObjectMetadata()
    header_keys = [c.lower() for c in response_headers.keys()]
    for key in FDSObjectMetadata.PRE_DEFINED_METADATA:
      if key.lower() in header_keys:
        metadata.add_header(key, response_headers[key])
    for key in response_headers:
      if key.lower().startswith(FDSObjectMetadata.USER_DEFINED_METADATA_PREFIX):
        metadata.add_user_metadata(key, response_headers[key])
    return metadata

  def list_all_objects(self, bucket_name, prefix='', delimiter=None):
    '''
    traverse all objects in the bucket
    :param bucket_name:
    :param prefix:
    :param delimiter:
    :return:
    '''
    result = self.list_objects(bucket_name, prefix, delimiter)
    while True:
      for object_summary in result.objects:
        yield object_summary
      if result.is_truncated:
        result = self.list_next_batch_of_objects(result)
      else:
        break

  def _update_bucket_versioning_(self, bucket_name, versioning):
    '''
    Update bucket versioning
    :param bucket_name:
    :param versioning:
    :return:
    '''
    uri = '%s%s' % (self._config.get_base_uri(), quote(bucket_name))
    response = self._request.put(uri, auth=self._auth, params={"versioning": str(versioning)})
    if response.status_code == requests.codes.ok:
      return to_json_object(response.content)
    else:
      headers = ""
      if self._config.debug:
        headers = ' header=%s' % response.headers
      message = 'Update bucket versioning failed, status=%s, reason=%s%s' % (
        response.status_code, response.content, headers)
      raise GalaxyFDSClientException(message)

  def _get_bucket_versioning_(self, bucket_name):
    '''
    Get bucket versioning
    :param bucket_name:
    :param versioning:
    :return:
    '''
    uri = '%s%s' % (self._config.get_base_uri(), quote(bucket_name))
    response = self._request.get(uri, auth=self._auth, params={"versioning": "true"})
    if response.status_code == requests.codes.ok:
      content = response.content
      if isinstance(content, bytes):
        content = content.decode(encoding='utf-8')
      return int(content)
    else:
      headers = ""
      if self._config.debug:
        headers = ' header=%s' % response.headers
      message = 'Get bucket versioning failed, status=%s, reason=%s%s' % (
        response.status_code, response.content, headers)
      raise GalaxyFDSClientException(message)

  def _list_version_ids_(self, bucket_name, object_name):
    '''
    List all version ids of specified object order by timestamp desc
    :param bucket_name:
    :param object_name:
    :return: a list of version ids of specified object
    '''
    uri = '%s%s/%s' % (self._config.get_base_uri(), quote(bucket_name), quote(object_name))
    response = self._request.get(uri, auth=self._auth, params={"versionIds": "true"})
    if response.status_code == requests.codes.ok:
      return to_json_object(response.content)
    else:
      headers = ""
      if self._config.debug:
        headers = ' header=%s' % response.headers
      message = 'Get object version ids failed, status=%s, reason=%s%s' % (
        response.status_code, response.content, headers)
      raise GalaxyFDSClientException(message)

  def update_lifecycle_config(self, bucket_name, lifecycle_config):
    '''
    Update lifecycle config of a bucket which determine by the config
    :param lifecycle_config:
    '''
    uri = '%s%s' % (self._config.get_base_uri(), quote(bucket_name))
    response = self._request.put(uri,
                                 auth=self._auth,
                                 params={"lifecycle": "true"},
                                 data=json.dumps(lifecycle_config))
    if response.status_code != requests.codes.ok:
      headers = ""
      if self._config.debug:
        headers = ' header=%s' % response.headers
      message = 'Update bucket lifecycle config failed, status=%s, reason=%s%s' % (
        response.status_code, response.content, headers)
      raise GalaxyFDSClientException(message)

  def update_lifecycle_rule(self, bucket_name, rule):
    '''
    Update a TTL rule of specified bucket
    :param rule: If rule.id is None or not exists in bucket.lifecycle_config, add rule with a generated ID. Otherwise bucket.lifecycle_config[rule.id] will be updated
    '''
    uri = '%s%s' % (self._config.get_base_uri(), quote(bucket_name))
    response = self._request.put(uri,
                                 auth=self._auth,
                                 params={"lifecycle": "rule"},
                                 data=json.dumps(rule))
    if response.status_code != requests.codes.ok:
      headers = ""
      if self._config.debug:
        headers = ' header=%s' % response.headers
      message = 'Update bucket lifecycle rule failed, status=%s, reason=%s%s' % (
        response.status_code, response.content, headers)
      raise GalaxyFDSClientException(message)

  def get_lifecycle_config(self, bucket_name, rule_id=None):
    '''
    Get lifecycle config of specified bucket
    :param bucket_name:
    :param rule_id: if rule_id is None, return lifecycle_config of the bucket; otherwise return bucket.lifecycle_config[rule_id], if the rule exists
    :return:
    '''
    uri = '%s%s' % (self._config.get_base_uri(), quote(bucket_name))
    response = self._request.get(uri, auth=self._auth,
                                 params={"lifecycle": rule_id and rule_id or ""})
    if response.status_code == requests.codes.ok:
      js = to_json_object(response.content)
      if rule_id:
        return FDSLifecycleRule(js)
      else:
        return FDSLifecycleConfig(js)
    else:
      headers = ""
      if self._config.debug:
        headers = ' header=%s' % response.headers
      message = 'Get bucket lifecycle config failed, status=%s, reason=%s%s' % (
        response.status_code, response.content, headers)
      raise GalaxyFDSClientException(message)

  def _set_bucket_default_webp_quality_(self, bucket_name, quality):
    '''
    Enable bucket auto convert webp.
    :param bucket_name:     The name of the bucket
    :param quality:         Default webp quality, -1 means disable auto convert webp
    '''
    uri = '%s%s' % (self._config.get_base_uri(), quote(bucket_name))
    response = self._request.put(uri, auth=self._auth, params={
      "webpQuality": str(quality)
    })
    if response.status_code != requests.codes.ok:
      headers = ""
      if self._config.debug:
        headers = ' header=%s' % response.headers
      message = 'Enable bucket auto convert webp failed, status=%s, reason=%s%s' % (
        response.status_code, response.content, headers)
      raise GalaxyFDSClientException(message)

  def _get_bucket_default_webp_quality_(self, bucket_name):
    '''
    Check the existence of a specified object.
    :param bucket_name: The name of the bucket
    :return: True if the object exists, otherwise, False
    '''
    uri = '%s%s' % (self._config.get_base_uri(), quote(bucket_name))
    response = self._request.get(uri, auth=self._auth, params={
      "webpQuality": "true"
    })
    if response.status_code == requests.codes.ok:
      content = response.content
      if IS_PY3:
        content = content.decode("UTF-8")
      return int(content)
    elif response.status_code == requests.codes.not_found:
      return False
    else:
      headers = ""
      if self._config.debug:
        headers = ' header=%s' % response.headers
      message = 'Check object existence failed, status=%s, reason=%s%s' % (
        response.status_code, response.content, headers)
      raise GalaxyFDSClientException(message)

  def _get_webp_(self, bucket_name, object_name, stream=None, quality=None):
    '''
    Get a specified object from a bucket.
    :param bucket_name: The name of the bucket from whom to get the object
    :param object_name: The name of the object to get
    :param stream:      Set True to enable streaming, otherwise, whole object content is read to memory
    :return: The FDS object
    '''
    uri = '%s%s/%s' % (self._config.get_download_base_uri(), quote(bucket_name), quote(object_name))
    params = {
      "f": "webp"
    }
    if quality:
      params["q"] = quality
    response = self._request.get(uri, auth=self._auth, stream=stream, params=params)

    if response.status_code == requests.codes.ok or \
        response.status_code == requests.codes.partial:
      obj = FDSObject()
      obj.stream = response.iter_content()
      summary = FDSObjectSummary()
      summary.bucket_name = bucket_name
      summary.object_name = object_name
      summary.size = int(response.headers['content-length'])
      obj.summary = summary
      obj.metadata = self._parse_object_metadata_from_headers(response.headers)
      return obj
    else:
      headers = ""
      if self._config.debug:
        headers = ' header=%s' % response.headers
      message = 'Get webp failed, status=%s, reason=%s%s' % (
        response.status_code, response.content, headers)
      raise GalaxyFDSClientException(message)

  def generate_anti_stealing_uri(self, bucket_name, object_name, expiration, key):
    '''
    Generate anti stealing URI
    :param bucket_name: The name of the bucket from whom to get the object
    :param object_name: The name of the object to get
    :param expiration : The timestamp of milliseconds from 1970-01-01-00:00:00
    :param key        : The key you set up for the bucket
    :return: The anti stealing URI
    '''
    return self._generate_anti_stealing_uri(self._config.get_base_uri(), bucket_name, object_name,
                                            expiration, key)

  def generate_anti_stealing_cdn_uri(self, bucket_name, object_name, expiration, key):
    '''
    Generate anti stealing CDN URI
    :param bucket_name: The name of the bucket from whom to get the object
    :param object_name: The name of the object to get
    :param expiration : The timestamp of milliseconds from 1970-01-01-00:00:00
    :param key        : The key you set up for the bucket
    :return: The anti stealing CDN URI
    '''
    return self._generate_anti_stealing_uri(self._config.get_cdn_base_uri(), bucket_name,
                                            object_name, expiration,
                                            key)

  def _generate_anti_stealing_uri(self, base_uri, bucket_name, object_name, expiration, key):
    timestamp = int(expiration) / 1000
    t = hex(timestamp).lstrip('0x')
    string_to_cal = key + '/' + bucket_name + '/' + object_name + t
    m = hashlib.md5()
    m.update(string_to_cal)
    sign = m.hexdigest()

    return "%s%s/%s?sign=%s&t=%s" % (base_uri, bucket_name, object_name, sign, t)

  def update_timestamp_anti_stealing_link_config(self, bucket_name, config):
    uri = '%s%s' % (self._config.get_base_uri(), quote(bucket_name))
    resp = self._request.put(uri, auth=self._auth, params={'antiStealingLink': 'true'},
                             data=json.dumps(config, default=lambda x: x.to_string()))

    if resp.status_code != requests.codes.ok:
      headers = ""
      if self._config.debug:
        headers = ' header=%s' % resp.headers
      message = 'Update timestamp anti stealing link config failed, status=%s, reason=%s%s' % (
        resp.status_code, resp.content, headers)
      raise GalaxyFDSClientException(message)

  def get_timestamp_anti_stealing_link_config(self, bucket_name):
    uri = '%s%s' % (self._config.get_base_uri(), quote(bucket_name))
    resp = self._request.get(uri, params={'antiStealingLink': 'true'}, auth=self._auth)

    if resp.status_code == requests.codes.ok:
      config = TimestampAntiStealingLinkConfig(to_json_object(resp.content))
      return config

    headers = ""
    if self._config.debug:
      headers = ' header=%s' % resp.headers
    message = 'Get timestamp anti stealing link config failed, status=%s, reason=%s%s' % (
      resp.status_code, resp.content, headers)
    raise GalaxyFDSClientException(message)

  def delete_timestamp_anti_stealing_link_config(self, bucket_name):
    uri = '%s%s' % (self._config.get_base_uri(), quote(bucket_name))
    resp = self._request.delete(uri, params={'antiStealingLink': 'true'}, auth=self._auth)

    if resp.status_code != requests.codes.ok:
      headers = ""
      if self._config.debug:
        headers = ' header=%s' % resp.headers
      message = 'Delete timestamp anti stealing link config failed, status=%s, reason=%s%s' % (
        resp.status_code, resp.content, headers)
      raise GalaxyFDSClientException(message)

  def _restore_archived_object_(self, bucket_name, object_name):
      '''
      Restore archived object as standard.
      If the object is ongoing restore, or not archived, raise exception
      :param bucket_name:     The name of the bucket
      :param object_name:     The name of the object
      '''
      uri = '%s%s/%s' % (self._config.get_base_uri(), quote(bucket_name), quote(object_name))
      response = self._request.put(uri,
                                   auth=self._auth,
                                   params={"restoreArchived": "true"})
      if response.status_code != requests.codes.ok:
          headers = ""
          if self._config.debug:
              headers = ' header=%s' % response.headers
          message = 'Restore archived object failed, status=%s, reason=%s%s' % (
              response.status_code, response.content, headers)
          raise GalaxyFDSClientException(message)

  def set_object_outside_access(self, bucket_name, object_name, value):
    if not isinstance(value, bool):
      raise GalaxyFDSClientException("value should be bool")
    uri = '%s%s/%s' % (self._config.get_base_uri(), quote(bucket_name), quote(object_name))
    response = self._request.put(uri, auth=self._auth, params={'setOutsideAccess': 'true' if value else 'false'})
    if response.status_code != requests.codes.ok:
      headers = ""
      if self._config.debug:
        headers = ' header=%s' % response.headers
      message = 'Set object outsideAccess failed, status=%s, reason=%s%s' % (
        response.status_code, response.content, headers)
      raise GalaxyFDSClientException(message)

  def set_bucket_outside_access(self, bucket_name, value):
    if not isinstance(value, bool):
      raise GalaxyFDSClientException("value should be bool")
    uri = '%s%s' % (self._config.get_base_uri(), quote(bucket_name))
    response = self._request.put(uri, auth=self._auth, params={'setOutsideAccess': 'true' if value else 'false'})
    if response.status_code != requests.codes.ok:
      headers = ""
      if self._config.debug:
        headers = ' header=%s' % response.headers
      message = 'Set bucket outsideAccess failed, status=%s, reason=%s%s' % (
        response.status_code, response.content, headers)
      raise GalaxyFDSClientException(message)