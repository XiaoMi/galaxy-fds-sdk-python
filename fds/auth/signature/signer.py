# -*- coding: utf-8 -*-
import base64
import hmac
from requests.auth import AuthBase
from hashlib import sha1
from urlparse import urlparse
from email.utils import formatdate

from fds.auth.common import Common
from fds.model.subresource import SubResource

class Signer(AuthBase):
  """Signer is used for authentication of FDS."""

  def __init__(self, app_key, app_secret, service_url=None):
    """Initialize with app_key and app_secret."""

    if service_url:
        self._service_base_url = service_url
    self._app_key = str(app_key)
    self._app_secret = str(app_secret)

  def __call__(self, r):
    """This is invoked when send requests with authentication."""

    r.headers[Common.DATE] = formatdate(timeval=None, localtime=False, usegmt=True)
    signature = self._get_signature(r.method, r.headers, r.url, self._app_secret)
    r.headers[Common.AUTHORIZATION] = 'Galaxy-V2 %s:%s' % (self._app_key, signature)
    return r

  @staticmethod
  def _get_signature(method, headers, url, app_secret):
    """Construct and return the signature for FDS."""

    string_to_sign = Signer._construct_string_to_sign(method, headers, url)
    h = hmac.new(app_secret, string_to_sign, digestmod=sha1)
    return base64.encodestring(h.digest()).strip()

  @staticmethod
  def _construct_string_to_sign(http_method, http_headers, uri):
    """Get header data to construct the string for signature."""

    result = ''
    result += '%s\n' % http_method
    result += '%s\n' % Signer._get_header_value(http_headers, Common.CONTENT_MD5)
    result += '%s\n' % Signer._get_header_value(http_headers, Common.CONTENT_TYPE)
    expires = Signer._get_expires(uri)
    if expires > 0:
      result += '%s\n' % expires
    else:
      xiaomi_date = Signer._get_header_value(http_headers, Common.XIAOMI_HEADER_DATE)
      date = ''
      if xiaomi_date is '':
        date = Signer._get_header_value(http_headers, Common.DATE)
      result += '%s\n' % date
    result += '%s' % Signer._canonicalize_xiaomi_headers(http_headers)
    result += '%s' % Signer._canonicalize_resource(uri)
    return result

  @staticmethod
  def _get_header_value(http_headers, name):
    """Get values from HTTP header."""

    if http_headers is not None and name in http_headers:
      value = http_headers[name]
      if type(value) is list:
        return http_headers[name][0]
      else:
        return value
    return ""

  @staticmethod
  def _canonicalize_xiaomi_headers(http_headers):
    """Canonicalize the standard headers for FDS."""

    if http_headers is None or http_headers == {}:
      return ''
    canonicalized_headers = {}
    for key in http_headers:
      lk = key.lower()
      try:
        lk = lk.decode('utf-8')
      except:
        pass
      if http_headers[key] and lk.startswith(Common.XIAOMI_HEADER_PREFIX):
        if type(http_headers[key]) != str:
          canonicalized_headers[lk] = ''
          i = 0
          for k in http_headers[key]:
            canonicalized_headers[lk] += '%s' % (k.strip())
            i += 1
            if i < len(http_headers[key]):
              canonicalized_headers[lk] += ','
        else:
          canonicalized_headers[lk] = http_headers[key].strip()
    result = ""
    for key in sorted(canonicalized_headers.keys()):
      values = canonicalized_headers[key]
      result += '%s:%s\n' % (key, values)
    return result

  @staticmethod
  def _canonicalize_resource(uri):
    """Canonicalize the standard resource."""

    result = ""
    parsedurl = urlparse(uri)
    result += '%s' % parsedurl.path
    query_args = parsedurl.query.split('&')
    i = 0
    for q in sorted(query_args):
      k = q.split('=')
      if k[0] in SubResource.get_all_subresource():
        if i == 0:
          result += '?'
        else:
          result += '&'
        if len(k) == 1:
          result += '%s' % k[0]
        else:
          result += '%s=%s' % (k[0], k[1])
        i += 1
    return result

  @staticmethod
  def _get_expires(uri):
    """Get the value of expires from uri."""

    parsed_url = urlparse(uri)
    query_args = sorted(parsed_url.query.split('&'))
    for q in query_args:
      k = q.split('=')[0]
      if k == Common.EXPIRES:
        return q.split('=')[1]
    return 0
