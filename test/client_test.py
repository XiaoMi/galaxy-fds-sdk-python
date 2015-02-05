#coding=utf-8
import unittest
import time
import urllib2

import sys
sys.path.append('../fds')

from galaxy_fds_client import GalaxyFDSClient
from galaxy_fds_client_exception import GalaxyFDSClientException
from fds_client_configuration import FDSClientConfiguration
from model.permission import Permission
from model.permission import AccessControlList
from model.permission import Grant
from model.permission import Grantee

class ClientTest(unittest.TestCase):

  def setUp(self):
    _access_key = "5341725076926"
    _access_secret = "vhlqXBAsWMbRIKZx+UBfPQ=="
    self.client = GalaxyFDSClient(_access_key, _access_secret,
        FDSClientConfiguration("staging", False, False, False))
    self.bucket_name = 'test-python-15652193901'

  def test_uri(self):
    access_key = "5341725076926"
    access_secret = "vhlqXBAsWMbRIKZx+UBfPQ=="
    client = GalaxyFDSClient(access_key, access_secret,
        FDSClientConfiguration("staging", False, False, False))
    client.create_bucket("66777")
    client.delete_bucket("66777")

  def test_normal_bucket(self):
    for bucket in self.client.list_buckets():
      print bucket
    bucket_name = "test-normal-bucket"
    self.assertFalse(self.client.does_bucket_exist(bucket_name))
    self.client.create_bucket(bucket_name)
    self.assertTrue(self.client.does_bucket_exist(bucket_name))
    self.client.delete_bucket(bucket_name)
    self.assertFalse(self.client.does_bucket_exist(bucket_name))

  def test_create_and_delete_bucket(self):
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

  def test_normal_object(self):
    object_name = "testPutGetObject_name"
    self.client.put_object(self.bucket_name, object_name, '')
    self.assertTrue(
      self.client.does_object_exists(self.bucket_name, object_name))
    print self.client.list_objects(self.bucket_name)
    self.client.delete_object(self.bucket_name, object_name)
    self.assertFalse(
      self.client.does_object_exists(self.bucket_name, object_name))
    print self.client.list_objects(self.bucket_name)

  def test_bucket_acl(self):
    self.client.get_bucket_acl(self.bucket_name)
    acl_ak = "5521728735794"
    acl_access_secret = "K7czwCuHODwZD49DD/qKzg=="
    bucketAcl = AccessControlList()
    bucketAcl.add_grant(Grant(Grantee("111"), Permission.READ))
    bucketAcl.add_grant(Grant(Grantee('109901'), Permission.FULL_CONTROL))
    self.client.set_bucket_acl(self.bucket_name, bucketAcl)
    acl = self.client.get_bucket_acl(self.bucket_name)
    self.assertTrue(bucketAcl.is_subset(acl))
    acl_client = GalaxyFDSClient(acl_ak, acl_access_secret,
        FDSClientConfiguration("staging", False, False, False))
    object_name = "testBucketAcl7"
    acl_client.put_object(self.bucket_name, object_name, "hahhah")
    self.assertTrue(
      self.client.does_object_exists(self.bucket_name, object_name))
    acl_client.list_objects(self.bucket_name)
    acl_client.delete_object(self.bucket_name, object_name)
    self.assertFalse(
      self.client.does_object_exists(self.bucket_name, object_name))
    self.assertTrue(acl_client.does_bucket_exist(self.bucket_name))
    try:
      acl_client.delete_bucket(self.bucket_name)
    except GalaxyFDSClientException as e:
      print e.message
    self.assertTrue(self.client.does_bucket_exist(self.bucket_name))

  def test_object_acl(self):
    object_name = "test1"
    content = "test1"
    self.client.put_object(self.bucket_name, object_name, content)
    for bucket in self.client.list_objects(self.bucket_name):
      print bucket
    print self.client.get_object_acl(self.bucket_name, object_name)
    acl_ak = "5521728735794"
    acl_access_secret = "K7czwCuHODwZD49DD/qKzg=="
    objectAcl = AccessControlList()
    objectAcl.add_grant(Grant(Grantee("111"), Permission.READ))
    objectAcl.add_grant(Grant(Grantee("109901"), Permission.FULL_CONTROL))
    self.client.set_object_acl(self.bucket_name, object_name, objectAcl)
    acl = self.client.get_object_acl(self.bucket_name, object_name)
    self.assertTrue(objectAcl.is_subset(acl))
    acl_client = GalaxyFDSClient(acl_ak, acl_access_secret,
        FDSClientConfiguration("staging", False, False, False))
    self.assertTrue(
        acl_client.does_object_exists(self.bucket_name, object_name))
    print acl_client.get_object(self.bucket_name, object_name)
    acl_client.delete_object(self.bucket_name, object_name)
    self.assertFalse(
        self.client.does_object_exists(self.bucket_name, object_name))

  def test_get_object_and_metadata(self):
    object_name = "test1"
    content = "test1"
    self.client.put_object(self.bucket_name, object_name, content)
    whole_object = self.client.get_object(self.bucket_name, object_name)
    self.assertEqual(whole_object.stream.next(), "test1")
    partial_object = self.client.get_object(self.bucket_name, object_name, 2)
    self.assertEqual(partial_object.stream.next(), "st1")
    metadata = self.client.get_object_metadata(self.bucket_name, object_name)
    print metadata.metadata

  def test_rename_object(self):
    object_old_name = "test_old1"
    object_new_name = "test_new1"
    self.client.put_object(self.bucket_name, object_old_name, "")
    self.assertTrue(
      self.client.does_object_exists(self.bucket_name, object_old_name))
    self.assertFalse(
      self.client.does_object_exists(self.bucket_name, object_new_name))
    self.client.rename_object(self.bucket_name, object_old_name, object_new_name)
    self.assertFalse(
      self.client.does_object_exists(self.bucket_name, object_old_name))
    self.assertTrue(
      self.client.does_object_exists(self.bucket_name, object_new_name))
    self.client.delete_object(self.bucket_name, object_new_name)

  def test_generate_presigned_uri(self):
    object_name = "中文测试"
    content = "presigned"
    self.client.put_object(self.bucket_name, object_name, content)
    uri = self.client.generate_presigned_uri(None, self.bucket_name, object_name,
                                             time.time() * 1000 + 60000)
    download = urllib2.urlopen(uri).read()
    self.assertEqual(content, download)

