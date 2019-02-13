# coding=utf-8
from __future__ import print_function

import unittest
from sys import version_info

import time

IS_PY3 = version_info[0] >= 3

if IS_PY3:
  from urllib.request import urlopen
else:
  from urllib2 import urlopen

import hashlib

import sys

sys.path.append('../')
import os
from os.path import expanduser

from fds.auth import Common
from fds.galaxy_fds_client import GalaxyFDSClient
from fds.fds_client_configuration import FDSClientConfiguration
from fds.model.fds_object_metadata import FDSObjectMetadata
from fds.model.permission import Permission
from fds.model.permission import AccessControlList
from fds.model.permission import Grant
from fds.model.permission import Grantee
from fds.model.upload_part_result_list import UploadPartResultList
from fds.model.fds_lifecycle import *
from fds.model.fds_cors import FDSCORSConfig,FDSCORSRule
import json

from datetime import datetime


class ClientTest(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    ClientTest.init_from_local_config()
    config = FDSClientConfiguration(
      region_name=region_name,
      enable_https=False,
      enable_cdn_for_upload=False,
      enable_cdn_for_download=False,
      endpoint=endpoint)
    config.enable_md5_calculate = True
    ClientTest.client = GalaxyFDSClient(access_key, access_secret, config)
    ClientTest.bucket_name = 'test-python-' + datetime.strftime(datetime.now(), "%Y%m%d%H%M%S%z")
    ClientTest.delete_objects_and_bucket(cls.client, cls.bucket_name)
    ClientTest.client.create_bucket(cls.bucket_name)

  @classmethod
  def tearDownClass(cls):
    ClientTest.delete_objects_and_bucket(ClientTest.client, ClientTest.bucket_name)

  @staticmethod
  def delete_objects_and_bucket(client, bucket_name):
    if client.does_bucket_exist(bucket_name):
      for obj in client.list_all_objects(bucket_name, delimiter=""):
        client.delete_object(bucket_name, obj.object_name)
      client.delete_bucket(bucket_name)

  @staticmethod
  def init_from_local_config():
    global access_key, access_secret, endpoint, app_id, acl_ak, acl_access_secret, region_name
    # if type(access_key) == str and access_key.strip() != "":
    #   return
    config_dirs = [os.path.join(expanduser("~"), ".config", "xiaomi", "config"),
                   os.path.join(expanduser("~"), ".config", "fds", "client.config")];
    config = {}
    for config_dir in config_dirs:
      if not os.path.exists(config_dir):
        pass
      else:
        with open(config_dir) as f:
          config = json.load(fp=f)
    access_key = config.get("xiaomi_access_key_id", "")
    access_secret = config.get("xiaomi_secret_access_key", "")
    endpoint = config.get("xiaomi_fds_endpoint", "")
    app_id = config.get("xiaomi_app_id", "")
    acl_ak = config.get("xiaomi_acl_access_key", "")
    acl_access_secret = config.get("xiaomi_acl_access_secret", "")
    region_name = config.get("xiaomi_region_name", "")

  def test_set_endpoint(self):
    httpConfig = FDSClientConfiguration(region_name, False, False, False)
    endpoint = region_name + ".api.xiaomi.net"
    httpConfig.set_endpoint(endpoint)
    httpUri = httpConfig.get_base_uri()
    self.assertEqual("http://" + endpoint + "/", httpUri)
    httpsConfig = FDSClientConfiguration(region_name, False, False, True)
    httpsConfig.set_endpoint(endpoint)
    httpsUri = httpsConfig.get_base_uri()
    self.assertEqual("https://" + endpoint + "/", httpsUri)

  def test_uri(self):
    client = GalaxyFDSClient(access_key, access_secret,
                             FDSClientConfiguration(region_name, False, False, False))
    bucket_name = self.bucket_name + "1"
    if (client.does_bucket_exist(bucket_name)):
      client.delete_bucket(bucket_name)
    client.create_bucket(bucket_name)
    client.delete_bucket(bucket_name)

  def test_normal_bucket(self):
    for bucket in self.client.list_buckets():
      print(bucket)
    bucket_name = self.bucket_name + "2"
    self.assertFalse(self.client.does_bucket_exist(bucket_name))
    self.client.create_bucket(bucket_name)
    self.assertTrue(self.client.does_bucket_exist(bucket_name))
    self.client.delete_bucket(bucket_name)
    self.assertFalse(self.client.does_bucket_exist(bucket_name))

  def test_create_and_delete_bucket(self):
    print(self.client.list_buckets())
    bucket_name = self.bucket_name + "3"
    try:
      self.client.create_bucket(bucket_name)
    except GalaxyFDSClientException as e:
      print(e.message)
    self.delete_objects_and_bucket(self.client, bucket_name)
    self.client.create_bucket(bucket_name)
    self.assertEquals(True, self.client.does_bucket_exist(bucket_name))
    self.client.delete_bucket(bucket_name)
    self.assertEquals(False, self.client.does_bucket_exist(bucket_name))
    try:
      self.client.delete_bucket(bucket_name)
    except GalaxyFDSClientException as e:
      print(e.message)

  def test_normal_object(self):
    object_name = "testPutGetObject_name"
    self.client.put_object(self.bucket_name, object_name, '')
    self.assertTrue(
      self.client.does_object_exists(self.bucket_name, object_name))
    print(self.client.list_objects(self.bucket_name))
    self.client.delete_object(self.bucket_name, object_name)
    self.assertFalse(
      self.client.does_object_exists(self.bucket_name, object_name))
    print(self.client.list_objects(self.bucket_name))

  def test_bucket_acl(self):
    print(self.bucket_name)

    self.client.get_bucket_acl(self.bucket_name)
    bucketAcl = AccessControlList()
    bucketAcl.add_grant(Grant(Grantee("111"), Permission.READ))
    bucketAcl.add_grant(Grant(Grantee('109901'), Permission.FULL_CONTROL))
    bucketAcl.add_grant(Grant(Grantee('123456'), Permission.SSO_WRITE))
    bucketAcl.add_grant(Grant(Grantee(app_id), Permission.FULL_CONTROL))
    self.client.set_bucket_acl(self.bucket_name, bucketAcl)

    aclListGot = self.client.get_bucket_acl(self.bucket_name)
    readAclCnt = 0
    fullControlCnt = 0
    writeWithSSOCnt = 0
    for i in aclListGot.get_grant_list():
      if i['grantee']['id'] == '111':
        self.assertTrue(i['permission'].to_string() == Permission(Permission.READ).to_string())
        readAclCnt += 1
      elif i['grantee']['id'] == '109901':
        self.assertTrue(
          i['permission'].to_string() == Permission(Permission.FULL_CONTROL).to_string())
        fullControlCnt += 1
      elif i['grantee']['id'] == '123456':
        self.assertTrue(i['permission'].to_string() == Permission(Permission.SSO_WRITE).to_string())
        writeWithSSOCnt += 1
    self.assertTrue(readAclCnt == 1)
    self.assertTrue(fullControlCnt == 1)
    self.assertTrue(writeWithSSOCnt == 1)

    #    self.client.set_bucket_acl(self.bucket_name, bucketAcl)
    acl = self.client.get_bucket_acl(self.bucket_name)
    self.assertTrue(bucketAcl.is_subset(acl))
    acl_client = GalaxyFDSClient(acl_ak, acl_access_secret,
                                 FDSClientConfiguration(region_name, False, False, False,
                                                        endpoint=endpoint))
    object_name = "testBucketAcl7"
    acl_client.put_object(self.bucket_name, object_name, "hahhah")
    self.assertTrue(
      self.client.does_object_exists(self.bucket_name, object_name))
    acl_client.list_objects(self.bucket_name)
    acl_client.delete_object(self.bucket_name, object_name)
    self.assertFalse(
      self.client.does_object_exists(self.bucket_name, object_name))
    self.assertTrue(acl_client.does_bucket_exist(self.bucket_name))

  #    acl_client.delete_bucket(self.bucket_name)
  #    self.assertFalse(self.client.does_bucket_exist(self.bucket_name))

  def test_object_acl(self):
    object_name = "test1"
    content = "test1"
    self.client.put_object(self.bucket_name, object_name, content)
    for bucket in self.client.list_objects(self.bucket_name):
      print(bucket)
    print(self.client.get_object_acl(self.bucket_name, object_name))
    objectAcl = AccessControlList()
    objectAcl.add_grant(Grant(Grantee("111"), Permission.READ))
    objectAcl.add_grant(Grant(Grantee("109901"), Permission.FULL_CONTROL))
    objectAcl.add_grant(Grant(Grantee(acl_ak), Permission.FULL_CONTROL))
    self.client.set_object_acl(self.bucket_name, object_name, objectAcl)
    acl = self.client.get_object_acl(self.bucket_name, object_name)
    self.assertTrue(objectAcl.is_subset(acl))

    acl_client = GalaxyFDSClient(acl_ak, acl_access_secret,
                                 FDSClientConfiguration(region_name, False, False, False,
                                                        endpoint=endpoint))
    self.assertTrue(
      self.client.does_object_exists(self.bucket_name, object_name))
    print(acl_client.get_object(self.bucket_name, object_name))
    self.client.delete_object(self.bucket_name, object_name)
    self.assertFalse(
      self.client.does_object_exists(self.bucket_name, object_name))

  def test_get_object_and_metadata(self):
    object_name = "test1"
    content = "test1"
    self.client.put_object(self.bucket_name, object_name, content)
    whole_object = self.client.get_object(self.bucket_name, object_name)
    self.assertEqual(whole_object.get_next_chunk_as_string(), "test1")
    partial_object = self.client.get_object(self.bucket_name, object_name, 2)
    self.assertEqual(partial_object.get_next_chunk_as_string(), "st1")
    metadata = self.client.get_object_metadata(self.bucket_name, object_name)
    if IS_PY3:
      self.assertEqual(hashlib.md5("test1".encode("UTF-8")).hexdigest(),
                       metadata.metadata["content-md5"])
    else:
      self.assertEqual(hashlib.md5("test1").hexdigest(), metadata.metadata["content-md5"])
    print(metadata.metadata)

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
    download = urlopen(uri).read()
    if IS_PY3:
      download = download.decode(encoding="UTF-8")
    self.assertEqual(content, download)

  def test_invalid_object_metadata(self):
    metadata = FDSObjectMetadata()

    metadata.add_user_metadata(FDSObjectMetadata.USER_DEFINED_METADATA_PREFIX
                               + "test", "test-value")
    metadata.add_header(Common.CACHE_CONTROL, "no-cache")

    try:
      metadata.add_user_metadata("test-key", "test-vale")
      self.fail("Exception should not be thrown here")
    except:
      pass

  def test_abort_multipart_upload(self):
    object_name = "test_object"
    upload_token = self.client.init_multipart_upload(self.bucket_name, object_name);
    self.client.abort_multipart_upload(self.bucket_name, object_name, upload_token.upload_id)

  def test_list_multi_objects(self):
    test_content = ""
    obj_prefix = "obj_"
    # add 2000 objects to make sure the result is truncated
    for i in range(2000):
      self.client.put_object(self.bucket_name, obj_prefix + str(i), test_content)
    for obj in self.client.list_all_objects(self.bucket_name):
      self.client.delete_object(self.bucket_name, obj.object_name)

  def test_multipart_upload(self):
    object_name = "test_multipart_upload"
    part_num = 3
    part_content = "1" * 5242880
    upload_list = []
    upload_token = self.client.init_multipart_upload(self.bucket_name, object_name)

    for i in range(part_num):
      upload_list.append(
        self.client.upload_part(self.bucket_name, object_name, upload_token.upload_id, i + 1,
                                part_content))

    upload_part_result = UploadPartResultList({"uploadPartResultList": upload_list})
    print(json.dumps(upload_part_result))
    self.client.complete_multipart_upload(bucket_name=self.bucket_name,
                                          object_name=object_name,
                                          upload_id=upload_token.upload_id,
                                          metadata=None,
                                          upload_part_result_list=json.dumps(upload_part_result))

    obj = self.client.get_object(self.bucket_name, object_name)
    length = 0
    for chunk in obj.stream:
      if IS_PY3:
        chunk = chunk.decode(encoding="UTF-8")
      length += len(chunk)
      for t in chunk:
        self.assertEqual(t, "1")

    obj.stream.close()
    print(length)
    self.assertEqual(length, part_num * 5242880)

  def test_delete_objects(self):
    total_count = 100;
    object_prefix = "delete-objs-";
    object_names = [""]
    for i in range(total_count):
      object_name = object_prefix + str(i)
      self.client.put_object(self.bucket_name, object_name, "")
      object_names.append(object_name)

    delete_result = self.client.delete_objects(self.bucket_name, object_names)
    self.assertEqual(len(self.client.list_objects(self.bucket_name).objects), 0)

  def test_list_trash(self):
    print("")
    total_count = 150;
    object_prefix = "trash-obj-";
    for i in range(total_count):
      self.client.put_object(self.bucket_name, object_prefix + str(i), "")

    self.client.delete_objects(self.bucket_name,
                               [object_prefix + str(i) for i in range(total_count)])

    list_result = self.client.list_trash_objects(self.bucket_name + "/trash-obj-", "", max_keys=50)
    sub_count1 = len(list_result.objects)
    self.assertEqual(50, sub_count1)
    print(list_result.next_marker)

    list_result = self.client.list_next_batch_of_objects(list_result)
    sub_count2 = len(list_result.objects)
    self.assertEqual(sub_count1 + sub_count2, total_count)

  def test_restore(self):
    print("")
    self.client.put_object(self.bucket_name, "aa/aa-1", "123")
    self.client.delete_object(self.bucket_name, "aa/aa-1")
    flag = False
    try:
      self.client.get_object(self.bucket_name, "aa/aa-1").get_next_chunk_as_string()
    except:
      flag = True

    self.assertTrue(flag)
    self.client.restore_object(self.bucket_name, "aa/aa-1")
    print(self.client.get_object(self.bucket_name, "aa/aa-1").get_next_chunk_as_string())

  def test_versioning(self):
    '''
    This test will not pass due to bucket cache in restserver
    :return:
    '''
    print("")
    versionings = [2, 3, 6, 7, 8, 12, 2]
    for v in versionings:
      self.client._update_bucket_versioning_(self.bucket_name, v)
      time.sleep(5)
      self.assertEqual(self.client._get_bucket_versioning_(self.bucket_name), v)

  def test_get_version_ids(self):
    print("")
    count = 10
    get_content = lambda i: "data-%d" % i

    for i in range(count):
      self.client.put_object(self.bucket_name, "obj", get_content(i))
    vids = self.client._list_version_ids_(self.bucket_name, "obj")
    self.assertEqual(len(vids), count - 1)
    for i, id in enumerate(reversed(vids)):
      self.assertEqual(get_content(i), self.client.get_object(self.bucket_name, "obj",
                                                              version_id=id).get_next_chunk_as_string())

  def test_lifecycle_config(self):
    print("")
    actions = [
      FDSNonCurrentVersionExpiration({"days": 0.01}),
      FDSExpiration({"days": 0.01}),
      FDSAbortIncompleteMultipartUpload({"days": 1}),
    ]

    rule1 = FDSLifecycleRule()
    rule1.enabled = True
    rule1.prefix = "image/"
    rule1.update_action(actions[0])
    rule1.update_action(actions[1])
    rule1.update_action(actions[2])

    rule2 = FDSLifecycleRule()
    rule2.enabled = True
    rule2.prefix = "image/tmp/"
    rule2.update_action(FDSExpiration({"days": 0.00001}))
    rule2.update_action(FDSNonCurrentVersionExpiration({"days": 0.00001}))

    ttlconfig = FDSLifecycleConfig()
    ttlconfig.rules.append(rule1)
    ttlconfig.rules.append(rule2)

    self.client.update_lifecycle_config(self.bucket_name, ttlconfig)
    print(json.dumps(self.client.get_lifecycle_config(self.bucket_name)))

    ttlconfig = self.client.get_lifecycle_config(self.bucket_name)
    self.assertIsNotNone(ttlconfig.get_rule_by_prefix("image/tmp/"))
    self.assertIsNotNone(ttlconfig.get_rule_by_object_name("image/tmp/123.jpg"))
    ttlconfig.get_rule_by_prefix("image/tmp/").enabled = False
    self.assertIsNotNone(ttlconfig.get_rule_by_object_name("image/tmp/123.jpg"))
    self.assertIsNotNone(
      ttlconfig.get_rule_by_object_name("image/tmp/123.jpg", enabled_rule_only=True))
    ttlconfig.get_rule_by_prefix("image/").enabled = False
    self.assertIsNotNone(ttlconfig.get_rule_by_object_name("image/tmp/123.jpg"))
    self.assertIsNone(
      ttlconfig.get_rule_by_object_name("image/tmp/123.jpg", enabled_rule_only=True))

    rule3 = FDSLifecycleRule()
    rule3.enabled = True
    rule3.prefix = "log/tmp/"
    rule3.update_action(FDSExpiration({"days": 0.001}))
    rule3.update_action(FDSNonCurrentVersionExpiration({"days": 0.001}))
    self.client.update_lifecycle_rule(self.bucket_name, rule3)
    rule = self.client.get_lifecycle_config(self.bucket_name, "3")
    self.assertEqual(rule.prefix, rule3.prefix)
    self.assertEqual(rule.prefix, rule3.prefix)
    self.assertEqual("3", rule.id)
    print(self.client.get_lifecycle_config(self.bucket_name))


  def test_cors_config(self):
    rule1=FDSCORSRule()
    rule1.id="1"
    rule1.allowOrigin='*'
    rule2=FDSCORSRule()
    rule2.id="2"
    rule2.allowOrigin='*.example.com'
    cors_config=FDSCORSConfig()
    cors_config.rules.append(rule1)
    cors_config.rules.append(rule2)
    self.client.update_cors_config(self.bucket_name,cors_config)
    print(json.dumps(self.client.get_cors_config(self.bucket_name)))
    cors_config=self.client.get_cors_config(self.bucket_name)
    self.assertIsNotNone(cors_config.get_rule_by_id("1"))
    self.assertIsNotNone(cors_config.get_rule_by_id("2"))

    rule3=FDSCORSRule()
    rule3.allowOrigin="https://cloud.d.xiaomi.net"
    self.client.update_cors_rule(self.bucket_name,rule3)
    rule = self.client.get_cors_config(self.bucket_name, "3")
    self.assertEqual("3", rule.id)
    self.assertEqual(rule.allowOrigin, rule3.allowOrigin)
    print(self.client.get_cors_config(self.bucket_name))


  def test_get_and_delete_version(self):
    print("")
    object_name = "test_get_and_delete_version"
    get_content = lambda i: "data-%d" % i

    result = self.client.put_object(self.bucket_name, object_name, get_content(0))
    self.assertIsNone(result.previous_version_id)

    count = 100
    for i in range(1, count + 1):
      result = self.client.put_object(self.bucket_name, object_name, get_content(i))
      previous_version_id = result.previous_version_id
      self.assertIsNotNone(previous_version_id)
      self.assertEqual(get_content(i - 1),
                       self.client.get_object(self.bucket_name, object_name,
                                              version_id=previous_version_id).get_next_chunk_as_string())

    vid = self.client.delete_object(self.bucket_name, object_name)
    self.assertIsNotNone(vid)
    self.assertEqual(get_content(count),
                     self.client.get_object(self.bucket_name, object_name,
                                            version_id=vid).get_next_chunk_as_string())

    vids = self.client._list_version_ids_(self.bucket_name, object_name)
    # get No.98
    self.assertEqual(get_content(98),
                     self.client.get_object(self.bucket_name, object_name,
                                            version_id=vids[2]).get_next_chunk_as_string())

  def test_auto_convert_webp(self):
    bucket_name = self.bucket_name + "-convert-webp"
    object_name = "test.jpg"

    try:
      if not self.client.does_bucket_exist(bucket_name):
        self.client.create_bucket(bucket_name)

      self.client._enable_auto_convert_webp_(bucket_name, True)
      self.assertTrue(self.client._is_enable_auto_convert_webp_(bucket_name))

      path = os.path.join(expanduser("~"), "webp-images/")
      for fn in os.listdir(path):
        if fn.endswith("jpg"):
          with open(path + fn, "rb") as f:
            self.client.put_object(bucket_name, fn, f)

      for fn in os.listdir(path):
        if fn.endswith("jpg"):
          fds_object = self.client._get_webp_(bucket_name, fn)
          with open(path + fn + ".webp", "wb") as f:
            for chunk in fds_object.stream:
              f.write(chunk)
    finally:
      ClientTest.delete_objects_and_bucket(self.client, bucket_name)

