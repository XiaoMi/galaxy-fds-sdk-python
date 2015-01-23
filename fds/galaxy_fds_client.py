import json

import requests

from auth.signature.signer import Signer
from galaxy_fds_client_exception import GalaxyFDSClientException
from model.access_control_policy import AccessControlPolicy
from model.fds_object_metadata import FDSObjectMetadata
from model.permission import AccessControlList
from model.permission import Grant
from model.permission import Grantee
from model.subresource import SubResource

class GalaxyFDSClient(object):
  '''
  Client for Galaxy FDS Service.
  '''

  def __init__(self, access_key, access_secret, config):
    '''
    :param access_key:    The app access key
    :param access_secret: The app access secret
    :param uri:           The FDS service's base uri
    '''
    self._delimiter = "/"
    self._access_key = access_key
    self._access_secret = access_secret
    self._auth = Signer(self._access_key, self._access_secret)
    self._config = config

  def does_bucket_exist(self, bucket_name):
    '''
    Check the existence of a specified bucket.
    :param bucket_name: The bucket name of the bucket to check
    :return: True if the bucket exists, otherwise False
    '''
    uri = '%s%s' % (self._config.get_base_uri(), bucket_name)
    response = requests.head(uri, auth=self._auth)
    if response.status_code == requests.codes.ok:
      return True
    elif response.status_code == requests.codes.not_found:
      return False
    else:
      message = 'Check bucket existence failed, status=%s, reason=%s' % (
        response.status_code, response.content)
      raise GalaxyFDSClientException(message)

  def list_buckets(self):
    '''
    List all the buckets of the current developer.
    :return: The listed buckets.
    '''
    uri = self._config.get_base_uri()
    response = requests.get(uri, auth=self._auth)
    if response.status_code != requests.codes.ok:
      message = 'List buckets failed, status=%s, reason=%s' % (
        response.status_code, response.content)
      raise GalaxyFDSClientException(message)
    elif response.content:
      buckets_list = []
      buckets = json.loads(response.content)['buckets']
      for bucket in buckets:
        buckets_list.append(bucket['name'])
      return buckets_list
    else:
      return list()

  def create_bucket(self, bucket_name):
    '''
    Create a bucket with the specified name.
    :param bucket_name: The name of the bucket to create
    '''
    uri = '%s%s' % (self._config.get_base_uri(), bucket_name)
    response = requests.put(uri, auth=self._auth)
    if response.status_code != requests.codes.ok:
      message = 'Create bucket failed, status=%s, reason=%s' % (
        response.status_code, response.content)
      raise GalaxyFDSClientException(message)

  def delete_bucket(self, bucket_name):
    '''
    Delete a bucket of a specified name.
    :param bucket_name: The name of the bucket to delete
    '''
    uri = '%s%s' % (self._config.get_base_uri(), bucket_name)
    response = requests.delete(uri, auth=self._auth)
    if (response.status_code != requests.codes.ok and
        response.status_code != requests.codes.not_found):
      message = 'Delete bucket failed, status=%s, reason=%s' % (
        response.status_code, response.content)
      raise GalaxyFDSClientException(message)

  def put_object(self, bucket_name, object_name, data, metadata=None):
    '''
    Put the object to a specified bucket. If a object with the same name already
    existed, it will be overwritten.
    :param bucket_name: The name of the bucket to whom the object is put
    :param object_name: The name of the object to put
    :param data:        The data to put, bytes or a file like object
    :param metadata:    The metadata of the object
    '''
    uri = '%s%s/%s' % (self._config.get_upload_base_uri(), bucket_name,
      object_name)
    response = requests.put(uri, data=data, auth=self._auth,
      headers=metadata)
    if response.status_code != requests.codes.ok:
      message = 'Put object failed, status=%s, reason=%s' % (
        response.status_code, response.content)
      raise GalaxyFDSClientException(message)

  def post_object(self, bucket_name, data, metadata=None):
    '''
    Post the object to a specified bucket. The object name will be generated
    by the server uniquely.
    :param bucket_name: The name of the bucket to whom the object is put
    :param data:        The data to put, bytes or a file like object
    :param metadata:    The metadata of the object
    '''
    uri = '%s%s/' % (self._config.get_upload_base_uri(), bucket_name)
    response = requests.post(uri, data=data, auth=self._auth,
      headers=metadata)
    if response.status_code != requests.codes.ok:
      message = 'Post object failed, status=%s, reason=%s' % (
        response.status_code, response.content)
      raise GalaxyFDSClientException(message)

  def get_object(self, bucket_name, object_name, streaming=False, size=4096):
    '''
    Get a specified object from a bucket.
    :param bucket_name: The name of the bucket from whom to get the object
    :param object_name: The name of the object to get
    :param streaming:   The flag of whether the object result should be return
                        as a iterator or not
    :param size:        The maximum size of each piece when return streaming is on
    :return: The object content or content iterator if streaming is on
    '''
    uri = '%s%s/%s' % (self._config.get_download_base_uri(), bucket_name,
      object_name)
    response = requests.get(uri, auth=self._auth)
    if response.status_code == requests.codes.ok:
      if not streaming:
        return response.content
      else:
        return response.iter_content(chunk_size=size)
    else:
      message = 'Get object failed, status=%s, reason=%s' % (
        response.status_code, response.content)
      raise GalaxyFDSClientException(message)

  def does_object_exists(self, bucket_name, object_name):
    '''
    Check the existence of a specified object.
    :param bucket_name: The name of the bucket
    :param object_name: The name of the object to check
    :return: True if the object exists, otherwise, Flase
    '''
    uri = '%s%s/%s' % (self._config.get_base_uri(), bucket_name, object_name)
    response = requests.head(uri, auth=self._auth)
    if response.status_code == requests.codes.ok:
      return True
    elif response.status_code == requests.codes.not_found:
      return False
    else:
      message = 'Check object existence failed, status=%s, reason=%s' % (
        response.status_code, response.content)
      raise GalaxyFDSClientException(message)

  def delete_object(self, bucket_name, object_name):
    '''
    Delete specified object.
    :param bucket_name: The name of the bucket
    :param object_name: The name of the object
    '''
    uri = '%s%s/%s' % (self._config.get_base_uri(), bucket_name, object_name)
    response = requests.delete(uri, auth=self._auth)
    if response.status_code != requests.codes.ok:
      message = 'Delete object failed, status=%s, reason=%s' % (
        response.status_code, response.content)
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
    response = requests.put(uri, auth=self._auth)
    if response.status_code != requests.codes.ok:
      message = 'Rename object failed, status=%s, reason=%s' % (
        response.status_code, response.content)
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
    response = requests.put(uri, auth=self._auth, data=json.dumps(acp))
    if response.status_code != requests.codes.ok:
      message = 'Set bucket acl failed, status=%s, reason=%s' % (
        response.status_code, response.content)
      raise GalaxyFDSClientException(message)

  def get_bucket_acl(self, bucket_name):
    '''
    Get the ACL of a specified bucket.
    :param bucket_name: The name of the bucket to get ACL
    :return: The got access control list
    '''
    uri = '%s%s?%s' % (self._config.get_base_uri(), bucket_name,
      SubResource.ACL)
    response = requests.get(uri, auth=self._auth)
    if response.status_code == requests.codes.ok:
      acp = AccessControlPolicy(json.loads(response.content))
      acl = self._acp_to_acl(acp)
      return acl
    else:
      message = 'Get bucket acl failed, status=%s, reason=%s' % (
        response.status_code, response.content)
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
    response = requests.put(uri, auth=self._auth, data=json.dumps(acp))
    if response.status_code != requests.codes.ok:
      message = 'Set object acl failed, status=%s, reason=%s' % (
        response.status_code, response.content)
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
    response = requests.get(uri, auth=self._auth)
    if response.status_code == requests.codes.ok:
      acp = AccessControlPolicy(json.loads(response.content))
      acl = self._acp_to_acl(acp)
      return acl
    else:
      message = 'Get object acl failed, status=%s, reason=%s' % (
        response.status_code, response.content)
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
    response = requests.get(uri, auth=self._auth)
    if response.status_code == requests.codes.ok:
      metadata = self._parse_object_metadata_from_headers(response.headers)
      return metadata
    else:
      message = 'Get object metadata failed, status=%s, reason=%s' % (
        response.status_code, response.content)
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

  def _acl_to_acp(self, acl):
    '''
    Translate AccessControlList to AccessControlPolicy.
    '''
    if acl is not None:
      acp = AccessControlPolicy()
      acp.access_control_list = acl.get_grant_list
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
