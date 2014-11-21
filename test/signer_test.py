# -*- coding: utf-8 -*-
import unittest

from fds.auth import Common
from fds.auth.signature import Signer


class SignerTest(unittest.TestCase):
  """Test the methods of Singer."""

  def testGetExpires(self):
    uri = '/fds/mybucket/photos/puppy.jpg?test&GalaxyAccessKeyId=' \
          'AKIAIOSFODNN7EXAMPLE&Expires=1141889120&Signature=vjbyPxybdZaNmGa%2ByT272YEAiv4%3D'
    self.assertEquals('1141889120', Signer._get_expires(uri))


  def testHeaderValue(self):
    header = {'Content-Type': 'application/json', 'x-xiaomi-xx': ['A', 'B', 'C']}
    self.assertEquals('application/json',
                      Signer._get_header_value(header, 'Content-Type'))
    self.assertEquals('A', Signer._get_header_value(header, 'x-xiaomi-xx'))
    self.assertEquals('', Signer._get_header_value(header, 'Content-MD5'))

  def testCanonicalHeader(self):
    headers = None
    self.assertEquals('', Signer._canonicalize_xiaomi_headers(headers))
    headers = {}
    headers['Content-Type'] = 'application/json'
    headers[Common.XIAOMI_HEADER_PREFIX + 'meta-username'] = ['x@xiaomi.com ', 'a@xiaomi.com ']
    headers[Common.XIAOMI_HEADER_PREFIX + 'date'] = 'Tue, 27 Mar 2007 21:20:26+000'
    self.assertEquals(
      Common.XIAOMI_HEADER_PREFIX + 'date:' + 'Tue, 27 Mar 2007 21:20:26+000\n' +
      Common.XIAOMI_HEADER_PREFIX + 'meta-username:x@xiaomi.com,a@xiaomi.com\n',
      Signer._canonicalize_xiaomi_headers(headers)
    )

  def testCanonicalResource(self):
    uri = '/fds/mybucket/?acl&a=1&b=2&c=3'
    canonicalized_resource = Signer._canonicalize_resource(uri)
    self.assertEquals('/fds/mybucket/?acl', canonicalized_resource)

    uri = '/fds/mybucket/test.txt?uploads&uploadId=xxx&partNumber=3&timestamp=12345566';
    canonicalized_resource = Signer._canonicalize_resource(uri)
    self.assertEquals('/fds/mybucket/test.txt?partNumber=3&uploadId=xxx&uploads',
                      canonicalized_resource)

  def testConstructStringToSign(self):
    http_method = 'GET'
    headers = None
    uri = '/fds/bucket/test.txt?uploads&uploadId=xx&partNumber=1'

    self.assertEquals('%s\n\n\n\n''/fds/bucket/test.txt?partNumber=1&uploadId=xx&uploads' % http_method,
                      Signer._construct_string_to_sign(http_method, headers, uri))

    headers = {}
    headers[Common.CONTENT_TYPE] = 'application/json'
    headers[Common.CONTENT_MD5] = '123131331313231'
    headers[Common.DATE] = 'Tue, 27 Mar 2007 21:20:26+0000'

    self.assertEquals('%s\n%s\n%s\n%s\n''/fds/bucket/test.txt?partNumber=1&uploadId=xx&uploads' % (
      http_method, headers[Common.CONTENT_MD5], headers[Common.CONTENT_TYPE], headers[Common.DATE]),
                    Signer._construct_string_to_sign(http_method, headers, uri))

    headers['%sdate' % Common.XIAOMI_HEADER_PREFIX] = 'Tue, 28 Mar 2007 21:20:26+0000'
    '%s\n%s\n%s\n\ndate:Tue, 28 Mar 2007 21:20:26+0000\n/fds/bucket/test.txt?partNumber=1&uploadId=xx&uploads'
    self.assertEquals(
      '%s\n%s\n%s\n\n%sdate:Tue, 28 Mar 2007 21:20:26+0000\n/fds/bucket/test.txt?partNumber=1&uploadId=xx&uploads' %
      (http_method, headers[Common.CONTENT_MD5], headers[Common.CONTENT_TYPE], Common.XIAOMI_HEADER_PREFIX),
      Signer._construct_string_to_sign(http_method, headers, uri))

    uri = '/fds/bucket/test.txt?GalaxyAccessKeyId=AKIAIOSFODNN7EXAMPLE' \
          '&Expires=1141889120&Signature=vjbyPxybdZaNmGa%2ByT272YEAiv4%3D'
    self.assertEquals('%s\n%s\n%s\n1141889120\n%sdate:Tue, 28 Mar 2007 21:20:26+0000\n/fds/bucket/test.txt' %
                    (http_method, headers[Common.CONTENT_MD5], headers[Common.CONTENT_TYPE],
                     Common.XIAOMI_HEADER_PREFIX),
                    Signer._construct_string_to_sign(http_method, headers, uri))
