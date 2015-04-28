import json
import hashlib
from urllib import quote

import requests

from auth.common import Common
from auth.signature.signer import Signer
from fds_client_configuration import FDSClientConfiguration
from fds_request import FDSRequest
from galaxy_fds_client_exception import GalaxyFDSClientException
from model.access_control_policy import AccessControlPolicy
from model.fds_bucket import FDSBucket
from model.fds_object import FDSObject
from model.fds_object_listing import FDSObjectListing
from model.fds_object_metadata import FDSObjectMetadata
from model.fds_object_summary import FDSObjectSummary
from model.permission import AccessControlList
from model.permission import Grant
from model.permission import Grantee
from model.permission import Owner
from model.put_object_result import PutObjectResult
from model.subresource import SubResource

class GalaxyFDSClient(object):
  '''
  Client for Galaxy FDS Service.
  '''

  def __init__(self, access_key, access_secret,
               config = FDSClientConfiguration()):
    '''
    :param access_key:    The app access key
    :param access_secret: The app access secret
    :param config:        The FDS service's config
    '''
    self._delimiter = "/"
    self._access_key = access_key
    self._access_secret = access_secret
    self._auth = Signer(self._access_key, self._access_secret)
    self._config = config
    self._request = FDSRequest(config.timeout, config.max_retries)

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
    uri = '%s%s' % (self._config.get_base_uri(), bucket_name)
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
      json_response = json.loads(response.content)
      buckets = json_response['buckets']
      owner = Owner().from_json(json_response['owner'])
      for bucket in buckets:
        buckets_list.append(FDSBucket(bucket['name'], owner))
      return buckets_list
    else:
      return list()

  def create_bucket(self, bucket_name):
    '''
    Create a bucket with the specified name.
    :param bucket_name: The name of the bucket to create
    '''
    uri = '%s%s' % (self._config.get_base_uri(), bucket_name)
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
    uri = '%s%s' % (self._config.get_base_uri(), bucket_name)
    response = self._request.delete(uri, auth=self._auth)
    if (response.status_code != requests.codes.ok and
        response.status_code != requests.codes.not_found):
      headers = ""
      if self._config.debug:
        headers = ' header=%s' % response.headers
      message = 'Delete bucket failed, status=%s, reason=%s%s' % (
        response.status_code, response.content, headers)
      raise GalaxyFDSClientException(message)

  def list_objects(self, bucket_name, prefix = '', delimiter = None):
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
    uri = '%s%s?prefix=%s&delimiter=%s' % \
        (self._config.get_base_uri(), bucket_name, prefix, delimiter)
    response = self._request.get(uri, auth=self._auth)
    if response.status_code == requests.codes.ok:
      objects_list = FDSObjectListing(json.loads(response.content))
      return objects_list
    else:
      headers = ""
      if self._config.debug:
        headers = ' header=%s' % response.headers
      message = 'List objects under bucket %s with prefix %s failed, ' \
          'status=%s, reason=%s%s' % \
          (bucket_name, prefix, response.status_code, response.content, headers)
      raise GalaxyFDSClientException(message)

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
    marker = previous.next_marker
    uri = "%s%s?prefix=%s&marker=%s" % \
        (self._config.get_base_uri(), bucket_name, prefix, marker)
    response = self._request.get(uri, auth=self._auth)
    if response.status_code == requests.codes.ok:
      objects_list = FDSObjectListing(json.loads(response.content))
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
    uri = '%s%s/%s' % (self._config.get_upload_base_uri(), bucket_name,
      object_name)
    if metadata is None:
      metadata = FDSObjectMetadata()
    if self._config.enable_md5_calculate:
      digest = hashlib.md5()
      digest.update(data)
      metadata.add_header(Common.CONTENT_MD5,digest.hexdigest())

    response = self._request.put(uri, data=data, auth=self._auth,
        headers=metadata.metadata)
    if response.status_code == requests.codes.ok:
      return PutObjectResult(json.loads(response.content))
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
    uri = '%s%s/' % (self._config.get_upload_base_uri(), bucket_name)
    if metadata is None:
      metadata = FDSObjectMetadata()
    if self._config.enable_md5_calculate:
      digest = hashlib.md5()
      digest.update(data)
      metadata.add_header(Common.CONTENT_MD5,digest.hexdigest())

    response = self._request.post(uri, data=data, auth=self._auth,
        headers=metadata.metadata)
    if response.status_code == requests.codes.ok:
      return PutObjectResult(json.loads(response.content))
    headers = ""
    if self._config.debug:
      headers = ' header=%s' % response.headers
    message = 'Post object failed, status=%s, reason=%s%s' % (
        response.status_code, response.content, headers)
    raise GalaxyFDSClientException(message)

  def get_object(self, bucket_name, object_name, position = 0, size=4096):
    '''
    Get a specified object from a bucket.
    :param bucket_name: The name of the bucket from whom to get the object
    :param object_name: The name of the object to get
    :param position: The start index of object to get
    :param size:        The maximum size of each piece when return streaming is on
    :return: The FDS object
    '''
    if position < 0:
      raise GalaxyFDSClientException("Seek position should be no less than 0")
    uri = '%s%s/%s' % (self._config.get_download_base_uri(), bucket_name,
      object_name)
    if position > 0:
      header = {Common.RANGE : 'bytes=%d-' % position}
      response = self._request.get(uri, auth=self._auth, headers=header)
    else:
      response = self._request.get(uri, auth=self._auth)
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

  def does_object_exists(self, bucket_name, object_name):
    '''
    Check the existence of a specified object.
    :param bucket_name: The name of the bucket
    :param object_name: The name of the object to check
    :return: True if the object exists, otherwise, False
    '''
    uri = '%s%s/%s' % (self._config.get_base_uri(), bucket_name, object_name)
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

  def delete_object(self, bucket_name, object_name):
    '''
    Delete specified object.
    :param bucket_name: The name of the bucket
    :param object_name: The name of the object
    '''
    uri = '%s%s/%s' % (self._config.get_base_uri(), bucket_name, object_name)
    response = self._request.delete(uri, auth=self._auth)
    if response.status_code != requests.codes.ok:
      headers = ""
      if self._config.debug:
        headers = ' header=%s' % response.headers
      message = 'Delete object failed, status=%s, reason=%s%s' % (
        response.status_code, response.content, headers)
      raise GalaxyFDSClientException(message)

  def rename_object(self, bucket_name, src_object_name, dst_object_name):
    '''
    Rename a specified object to a new name.
    :param bucket_name:     The name of the bucket
    :param src_object_name: The original name of the object
    :param dst_object_name: The target name of the object to rename to
    '''
    uri = '%s%s/%s?renameTo=%s' % (self._config.get_base_uri(),
      bucket_name, src_object_name, dst_object_name)
    response = self._request.put(uri, auth=self._auth)
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
    uri = '%s%s?%s' % (self._config.get_base_uri(), bucket_name,
      SubResource.ACL)
    acp = self._acl_to_acp(acl)
    response = self._request.put(uri, auth=self._auth, data=json.dumps(acp,
        default=lambda x : x.to_string()))
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
    uri = '%s%s?%s' % (self._config.get_base_uri(), bucket_name,
      SubResource.ACL)
    response = self._request.get(uri, auth=self._auth)
    if response.status_code == requests.codes.ok:
      acp = AccessControlPolicy(json.loads(response.content))
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
    uri = '%s%s/%s?%s' % (
      self._config.get_base_uri(), bucket_name, object_name, SubResource.ACL)
    acp = self._acl_to_acp(acl)
    response = self._request.put(uri, auth=self._auth, data=json.dumps(acp,
        default=lambda x : x.to_string()))
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
    uri = '%s%s/%s?%s' % (
      self._config.get_base_uri(), bucket_name, object_name, SubResource.ACL)
    response = self._request.get(uri, auth=self._auth)
    if response.status_code == requests.codes.ok:
      acp = AccessControlPolicy(json.loads(response.content))
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
    uri = '%s%s/%s?%s' % (
      self._config.get_base_uri(), bucket_name, object_name,
        SubResource.METADATA)
    response = self._request.get(uri, auth=self._auth)
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

  def generate_presigned_uri(self, base_uri, bucket_name, object_name,
                             expiration, http_method = "GET"):
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
      base_uri = self._config.get_download_base_uri()
    try:
      uri = '%s%s/%s?%s=%s&%s=%s&' % \
            (base_uri, bucket_name, object_name, \
             Common.GALAXY_ACCESS_KEY_ID, self._auth._app_key, \
             Common.EXPIRES, str(int(expiration)))
      signature = str(self._auth._sign_to_base64(http_method, None, uri, \
                                                 self._auth._app_secret))
      return '%s%s/%s?%s=%s&%s=%s&%s=%s' % \
             (base_uri, quote(bucket_name), quote(object_name), \
              Common.GALAXY_ACCESS_KEY_ID, self._auth._app_key, \
              Common.EXPIRES, str(int(expiration)), Common.SIGNATURE, signature)
    except Exception, e:
      message = 'Wrong expiration given. ' \
                'Milliseconds since January 1, 1970 should be used. ' + str(e)
      raise GalaxyFDSClientException(message)

  def generate_download_object_uri(self, bucket_name, object_name):
    '''
    Generate a URI for downloading object
    '''
    return '%s%s/%s' % (self._config.get_download_base_uri(), bucket_name,
      object_name)

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

  def _acl_to_acp(self, acl):
    '''
    Translate AccessControlList to AccessControlPolicy.
    '''
    if acl is not None:
      acp = AccessControlPolicy(None)
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
    header_keys = response_headers.keys()
    for key in FDSObjectMetadata.PRE_DEFINED_METADATA:
      if key in header_keys:
        metadata.add_header(key, response_headers[key])
    for key in response_headers:
      if key.startswith(FDSObjectMetadata.USER_DEFINED_METADATA_PREFIX):
        metadata.add_user_metadata(key, response_headers[key])
    return metadata
