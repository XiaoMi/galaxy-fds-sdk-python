# -*- coding: utf-8 -*-
import unittest

from fds.galaxy_fds_client import GalaxyFDSClient
from fds.galaxy_fds_client_exception import GalaxyFDSClientException
from fds.model.permission import Permission
from fds.model.permission import AccessControlList
from fds.model.permission import Grant
from fds.model.permission import Grantee


class ClientTest(unittest.TestCase):
  """Test the methods of GalaxyFDSClient."""

  def setUp(self):
    _access_key = "your_access_key"
    _access_secret = "your_access_secret"
    self.client = GalaxyFDSClient(_access_key, _access_secret)
    self.bucket_name = 'test-python-15652193901'

  def testUri(self):
    access_key = "your_access_key"
    access_secret = "your_access_secret"
    uri = "http://files.fds.api.xiaomi.com"
    client = GalaxyFDSClient(access_key, access_secret, uri)
    client.create_bucket("66777")
    client.delete_bucket("66777")

  def testNormalBucket(self):
    print self.client.list_buckets()
    bucket_name = "testNormalBucket"
    self.assertFalse(self.client.does_bucket_exist(bucket_name))
    self.client.create_bucket(bucket_name)
    self.assertTrue(self.client.does_bucket_exist(bucket_name))
    self.client.delete_bucket(bucket_name)
    self.assertFalse(self.client.does_bucket_exist(bucket_name))

  def testCreateAndDeleteBucket(self):
    print self.client.list_buckets()
    try:
      self.client.create_bucket(self.bucket_name)
    except GalaxyFDSClientException as e:
      print e.message
    bucket_name = 'test-python-15652193901-python'
    self.client.create_bucket(bucket_name)
    self.assertEquals(True, self.client.does_bucket_exist(bucket_name))
    self.client.delete_bucket(bucket_name)
    self.assertEquals(False, self.client.does_bucket_exist(bucket_name))
    try:
      self.client.delete_bucket(bucket_name)
    except GalaxyFDSClientException as e:
      print e.message

  def testNormalObject(self):
    object_name = "testPutGetObject_name"
    self.client.put_object(self.bucket_name, object_name, '')
    self.assertTrue(self.client.does_object_exist(self.bucket_name, object_name))
    print self.client.list_objects(self.bucket_name)
    self.client.delete_object(self.bucket_name, object_name)
    self.assertFalse(self.client.does_object_exist(self.bucket_name, object_name))
    print self.client.list_objects(self.bucket_name)

  def testBucketAcl(self):
    self.client.get_bucket_acl(self.bucket_name)
    acl_ak = "your_access_key"
    acl_access_secret = "your_access_secret"
    bucketAcl = AccessControlList()
    bucketAcl.add_grant(Grant(Grantee("111"), Permission.READ))
    bucketAcl.add_grant(Grant(Grantee(acl_ak), Permission.FULL_CONTROL))
    self.client.set_bucket_acl(self.bucket_name, bucketAcl)
    self.client.get_bucket_acl(self.bucket_name)
    acl_client = GalaxyFDSClient(acl_ak, acl_access_secret)
    object_name = "testBucketAcl"
    acl_client.put_object(self.bucket_name, object_name, "hahhah")
    self.assertTrue(self.client.does_object_exist(self.bucket_name, object_name))
    acl_client.list_objects(self.bucket_name)
    acl_client.delete_object(self.bucket_name, object_name)
    self.assertFalse(self.client.does_object_exist(self.bucket_name, object_name))
    self.assertTrue(acl_client.does_bucket_exist(self.bucket_name))
    try:
      acl_client.delete_bucket(self.bucket_name)
    except GalaxyFDSClientException as e:
      print e.message
    self.assertTrue(self.client.does_bucket_exist(self.bucket_name))

  def testObjectAcl(self):
    object_name = "test1"
    content = "test1"
    self.client.put_object(self.bucket_name, object_name, content)
    print self.client.list_objects(self.bucket_name)
    print self.client.get_object_acl(self.bucket_name, object_name)
    acl_ak = "your_access_key"
    acl_access_secret = "your_access_secret"
    objectAcl = AccessControlList()
    objectAcl.add_grant(Grant(Grantee("111"), Permission.READ))
    objectAcl.add_grant(Grant(Grantee(acl_ak), Permission.FULL_CONTROL))
    self.client.set_object_acl(self.bucket_name, object_name, objectAcl)
    acl_client = GalaxyFDSClient(acl_ak, acl_access_secret)
    self.assertTrue(acl_client.does_object_exist(self.bucket_name, object_name))
    print acl_client.get_object(self.bucket_name, object_name)
    acl_client.delete_object(self.bucket_name, object_name)
    self.assertFalse(self.client.does_object_exist(self.bucket_name, object_name))

  def testGetObjectMetadata(self):
    object_name = "test1"
    content = "test1"
    self.client.put_object(self.bucket_name, object_name, content)
    metadata = self.client.get_object_metadata(self.bucket_name, object_name)
    print metadata.metadata
