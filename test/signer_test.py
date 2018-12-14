import sys
import unittest

sys.path.append('../')
from fds.auth import Common
from fds.auth.signature import Signer


class SignerTest(unittest.TestCase):
  signer = Signer('', '')

  def test_get_expires(self):
    uri = '/fds/mybucket/photos/puppy.jpg?test&GalaxyAccessKeyId=' \
          'AKIAIOSFODNN7EXAMPLE&Expires=1141889120&Signature=vjby' \
          'PxybdZaNmGa%2ByT272YEAiv4%3D'
    self.assertEqual(1141889120, self.signer._get_expires(uri))

  def test_header_value(self):
    header = {'Content-Type': 'application/json',
              'x-xiaomi-xx': ['A', 'B', 'C']}
    self.assertEquals('application/json',
                      self.signer._get_header_value(header, 'Content-Type'))
    self.assertEquals('A', self.signer._get_header_value(header, 'x-xiaomi-xx'))
    self.assertEquals('', self.signer._get_header_value(header, 'Content-MD5'))

  def test_canonical_header(self):
    headers = None
    self.assertEqual('', self.signer._canonicalize_xiaomi_headers(headers))
    headers = {}
    headers['Content-Type'] = 'application/json'
    headers[Common.XIAOMI_HEADER_PREFIX + 'meta-username'] = ['x@xiaomi.com ',
                                                              'a@xiaomi.com ']
    headers[
      Common.XIAOMI_HEADER_PREFIX + 'date'] = 'Tue, 27 Mar 2007 21:20:26+000'
    self.assertEqual(
      Common.XIAOMI_HEADER_PREFIX + 'date:' + 'Tue, 27 Mar 2007 21:20:26+000\n'
      + Common.XIAOMI_HEADER_PREFIX + 'meta-username:x@xiaomi.com,a@xiaomi.com\n',
      self.signer._canonicalize_xiaomi_headers(headers))

  def test_canonical_resource(self):
    uri = '/fds/mybucket/?acl&a=1&b=2&c=3'
    canonicalized_resource = self.signer._canonicalize_resource(uri)
    self.assertEqual('/fds/mybucket/?acl', canonicalized_resource)

    uri = '/fds/mybucket/test.txt?uploads&uploadId=xxx&partNumber=3&' \
          'timestamp=12345566';
    canonicalized_resource = self.signer._canonicalize_resource(uri)
    self.assertEqual(
      '/fds/mybucket/test.txt?partNumber=3&uploadId=xxx&uploads',
      canonicalized_resource)

  def test_construct_string_to_sign(self):
    http_method = 'GET'
    headers = None
    uri = '/fds/bucket/test.txt?uploads&uploadId=xx&partNumber=1'

    self.assertEquals('%s\n\n\n\n' \
                      '/fds/bucket/test.txt?partNumber=1&uploadId=xx&uploads' %
                      http_method,
                      self.signer._construct_string_to_sign(http_method, headers, uri))

    headers = {}
    headers[Common.CONTENT_TYPE] = 'application/json'
    headers[Common.CONTENT_MD5] = '123131331313231'
    headers[Common.DATE] = 'Tue, 27 Mar 2007 21:20:26+0000'

    self.assertEquals(
      '%s\n%s\n%s\n%s\n''/fds/bucket/test.txt?partNumber=1&uploadId=xx&uploads' % (
        http_method, headers[Common.CONTENT_MD5], headers[Common.CONTENT_TYPE],
        headers[Common.DATE]),
      self.signer._construct_string_to_sign(http_method, headers, uri))

    headers['%sdate' % Common.XIAOMI_HEADER_PREFIX] = \
      'Tue, 28 Mar 2007 21:20:26+0000'
    self.assertEquals(
      '%s\n%s\n%s\n\n%sdate:Tue, 28 Mar 2007 21:20:26+0000\n' \
      '/fds/bucket/test.txt?partNumber=1&uploadId=xx&uploads' % (
        http_method,
        headers[Common.CONTENT_MD5],
        headers[Common.CONTENT_TYPE],
        Common.XIAOMI_HEADER_PREFIX),
      self.signer._construct_string_to_sign(http_method, headers, uri))

    uri = '/fds/bucket/test.txt?GalaxyAccessKeyId=AKIAIOSFODNN7EXAMPLE' \
          '&Expires=1141889120&Signature=vjbyPxybdZaNmGa%2ByT272YEAiv4%3D'
    self.assertEquals(
      '%s\n%s\n%s\n1141889120\n%sdate:Tue, 28 Mar 2007 21:20:26+0000\n' \
      '/fds/bucket/test.txt' % (
        http_method,
        headers[Common.CONTENT_MD5],
        headers[Common.CONTENT_TYPE],
        Common.XIAOMI_HEADER_PREFIX),
      self.signer._construct_string_to_sign(http_method, headers, uri))
