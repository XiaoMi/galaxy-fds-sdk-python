import unittest

from fds.fdscli_cli import FDSURL


class TestFDSURL(unittest.TestCase):
  def setUp(self):
    self.a = FDSURL("fds://bucket_name")
    self.b = FDSURL("fds://bucket_name/")
    self.c = FDSURL("fds://bucket_name/object_prefix/object_name")
    self.d = FDSURL("fds://bucket_name/prefix/dir_name/")

  def test_is_fds_url(self):
    self.assertTrue(FDSURL.is_fds_url("fds://bucket_name"))
    self.assertFalse(FDSURL.is_fds_url("dd/fdsurl"))

  def test_is_absolute_bucket_url(self):
    self.assertTrue(self.a.is_bucket_url())
    self.assertTrue(self.b.is_bucket_url())
    self.assertFalse(self.c.is_bucket_url())
    self.assertFalse(self.d.is_bucket_url())

  def test_bucket_name(self):
    self.assertEqual(self.a.bucket_name(), "bucket_name")
    self.assertEqual(self.b.bucket_name(), "bucket_name")
    self.assertEqual(self.c.bucket_name(), "bucket_name")
    self.assertEqual(self.d.bucket_name(), "bucket_name")

  def test_object_name(self):
    self.assertIsNone(self.a.object_name())
    self.assertIsNone(self.b.object_name())

    self.assertEqual(self.c.object_name(), "object_prefix/object_name")
    self.assertIsNone(self.d.object_name())

  def test_is_dir(self):
    self.assertFalse(self.a.is_dir())
    self.assertTrue(self.b.is_dir())
    self.assertFalse(self.c.is_dir())
    self.assertTrue(self.d.is_dir())

  def test_is_bucket_dir(self):
    self.assertFalse(self.a.is_bucket_dir())
    self.assertTrue(self.b.is_bucket_dir())
    self.assertFalse(self.c.is_bucket_dir())
    self.assertFalse(self.d.is_bucket_dir())

  def test_is_object_dir(self):
    self.assertFalse(self.a.is_object_dir())
    self.assertFalse(self.b.is_object_dir())
    self.assertFalse(self.c.is_object_dir())
    self.assertTrue(self.d.is_object_dir())

  def test_object_dir(self):
    self.assertIsNone(self.a.object_dir())
    self.assertIsNone(self.b.object_dir())
    self.assertIsNone(self.c.object_dir())
    self.assertEqual(self.d.object_dir(), "prefix/dir_name/")

  def test_is_object_url(self):
    self.assertFalse(self.a.is_object_url())
    self.assertFalse(self.b.is_object_url())
    self.assertTrue(self.c.is_object_url())
    self.assertFalse(self.d.is_object_url())


if __name__ == "__main__":
  unittest.main()
