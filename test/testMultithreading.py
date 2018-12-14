# coding=utf-8
import sys
import unittest

sys.path.append('../')

from multiprocessing.pool import ThreadPool
from fds import GalaxyFDSClient
from fds.fds_client_configuration import FDSClientConfiguration
from test.test_common import region_name, access_key, access_secret


class multithreadingClientTest(unittest.TestCase):
  def setUp(self):
    config = FDSClientConfiguration(region_name, False, False, False)
    self.client = GalaxyFDSClient(access_key, access_secret, config)
    self.bucket_name = "1024"

  def checkAndDeleteBucket(self, index):
    for i in range(50):
      self.client.list_objects(self.bucket_name, "", "/")
    print
    index

  def testMultithreadingClient(self):
    pool = ThreadPool(50)
    if not self.client.does_bucket_exist(self.bucket_name):
      self.client.create_bucket(self.bucket_name)
    pool.map(self.checkAndDeleteBucket, range(50))
    pool.close()
    pool.join()
