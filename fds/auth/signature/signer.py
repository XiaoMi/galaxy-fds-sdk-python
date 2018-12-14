import base64
import hmac
from email.utils import formatdate
from hashlib import sha1
from sys import version_info

from requests.auth import AuthBase

IS_PY3 = version_info[0] >= 3
if IS_PY3:
  from urllib.parse import unquote, urlparse
else:
  from urllib import unquote
  from urlparse import urlparse

from fds.auth.common import Common
from fds.model.subresource import SubResource


class Signer(AuthBase):
  '''
  The signer class used to sign the request.
  '''

  def __init__(self, app_key, app_secret, service_url=None):
    if service_url:
      self._service_base_url = service_url
    self._app_key = str(app_key)
    self._app_secret = str(app_secret)

  def __call__(self, request):
    request.headers[Common.DATE] = formatdate(timeval=None, localtime=False,
                                              usegmt=True)
    signature = self._sign_to_base64(request.method, request.headers,
                                     unquote(request.url), self._app_secret)
    request.headers[Common.AUTHORIZATION] = 'Galaxy-V2 %s:%s' % (
      self._app_key, signature)
    return request

  def _sign(self, method, headers, url, app_secret):
    '''
    Sign the specified http request.
    :param method:     The request method to sign
    :param headers:    The request headers to sign
    :param url:        The request uri to sign
    :param app_secret: The secret used to sign the request
    :return: The signed result, aka the signature
    '''
    string_to_sign = self._construct_string_to_sign(method, headers, url)
    if IS_PY3:
      if isinstance(app_secret, str):
        app_secret = app_secret.encode(encoding='utf-8')
      if isinstance(string_to_sign, str):
        string_to_sign = string_to_sign.encode(encoding='utf-8')
    digest = hmac.new(app_secret, string_to_sign, digestmod=sha1)
    return digest.digest()

  def _sign_to_base64(self, method, headers, url, app_secret):
    '''
    Sign the specified request to base64 encoded result.
    :param method:     The request method to sign
    :param headers:    The request headers to sign
    :param url:        The request uri to sign
    :param app_secret: The secret used to sign the request
    :return: The signed result, aka the signature
    '''
    signature = self._sign(method, headers, url, app_secret)
    if IS_PY3:
      return base64.encodebytes(signature).decode(encoding='utf-8').strip()
    else:
      return base64.encodestring(signature).strip()

  def _construct_string_to_sign(self, http_method, http_headers, uri):
    '''
    Construct the string used to sign the request.
    '''
    result = str()
    result += '%s\n' % http_method
    result += '%s\n' % self._get_header_value(http_headers,
                                              Common.CONTENT_MD5)
    result += '%s\n' % self._get_header_value(http_headers,
                                              Common.CONTENT_TYPE)
    expires = self._get_expires(uri)

    if expires > 0:
      result += '%s\n' % expires
    else:
      xiaomi_date = self._get_header_value(http_headers,
                                           Common.XIAOMI_HEADER_DATE)
      date = str()
      if len(xiaomi_date) == 0:
        date = self._get_header_value(http_headers, Common.DATE)
      result += '%s\n' % date

    result += '%s' % self._canonicalize_xiaomi_headers(http_headers)
    result += '%s' % self._canonicalize_resource(uri)
    return result

  def _get_header_value(self, http_headers, name):
    if http_headers is not None and name in http_headers:
      value = http_headers[name]
      if type(value) is list:
        return http_headers[name][0]
      else:
        return value
    return ""

  def _canonicalize_xiaomi_headers(self, http_headers):
    if http_headers is None or len(http_headers) == 0:
      return ''

    canonicalized_headers = dict()
    for key in http_headers:
      lower_key = key.lower()
      try:
        lower_key = lower_key.decode('utf-8')
      except:
        pass

      if http_headers[key] and lower_key.startswith(Common.XIAOMI_HEADER_PREFIX):
        if type(http_headers[key]) != str:
          canonicalized_headers[lower_key] = str()
          i = 0
          for k in http_headers[key]:
            canonicalized_headers[lower_key] += '%s' % (k.strip())
            i += 1
            if i < len(http_headers[key]):
              canonicalized_headers[lower_key] += ','
        else:
          canonicalized_headers[lower_key] = http_headers[key].strip()

    result = ""
    for key in sorted(canonicalized_headers.keys()):
      values = canonicalized_headers[key]
      result += '%s:%s\n' % (key, values)
    return result

  def _canonicalize_resource(self, uri):
    result = ""
    parsed_url = urlparse(uri)
    result += '%s' % parsed_url.path
    query_args = parsed_url.query.split('&')

    i = 0
    for query in sorted(query_args):
      key = query.split('=')
      if key[0] in SubResource.get_all_subresource():
        if i == 0:
          result += '?'
        else:
          result += '&'
        if len(key) == 1:
          result += '%s' % key[0]
        else:
          result += '%s=%s' % (key[0], key[1])
        i += 1
    return result

  def _get_expires(self, uri):
    parsed_url = urlparse(uri)
    query_args = sorted(parsed_url.query.split('&'))
    for query in query_args:
      key = query.split('=')[0]
      if key == Common.EXPIRES:
        return int(query.split('=')[1])
    return 0
