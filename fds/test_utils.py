import unittest

import utils


class UtilsTest(unittest.TestCase):

  def test_rui_to_bucket_and_object(self):
    uri = "http://bucket1/object1"
    bucket, object = utils.uri_to_bucket_and_object(uri)
    self.assertEquals(bucket, None)
    self.assertEquals(object, None)

    uri = "fds://bucket1/object1"
    bucket, object = utils.uri_to_bucket_and_object(uri)
    self.assertEquals(bucket, "bucket1")
    self.assertEquals(object, "object1")

    uri = "fds://bucket1/folder1/folder2/object1"
    bucket, object = utils.uri_to_bucket_and_object(uri)
    self.assertEquals(bucket, "bucket1")
    self.assertEquals(object, "folder1/folder2/object1")


if __name__ == "__main__":
  unittest.main()
