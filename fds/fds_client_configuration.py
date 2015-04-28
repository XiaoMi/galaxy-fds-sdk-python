class FDSClientConfiguration(object):

  HTTP = 'http://'

  HTTPS = 'https://'

  BASE_HTTP_HOST = 'files.fds.api.xiaomi.com'

  BASE_CDN_HTTP_HOST = 'cdn.fds.api.xiaomi.com'

  BASE_HTTPS_HOST = 'files.fds.api.xiaomi.com'

  BASE_CDN_HTTPS_HOST = 'cdn.fds-ssl.api.xiaomi.com'

  def __init__(self, region_name = '',
      enable_cdn_for_download = True,
      enable_cdn_for_upload = False,
      enable_https = True,
      timeout = 30,
      max_retries = 3):
    self._region_name = region_name
    self._enable_cdn_for_download = enable_cdn_for_download
    self._enable_cdn_for_upload = enable_cdn_for_upload
    self._enable_https = enable_https
    self._enable_md5_calculate = False
    self._timeout = timeout
    self._max_retries = max_retries
    self._debug = False

  @property
  def debug(self):
    return self._debug

  @debug.setter
  def debug(self, debug):
    self._debug = debug

  @property
  def enable_md5_calculate(self):
    return self._enable_md5_calculate

  @enable_md5_calculate.setter
  def enable_md5_calculate(self, enable):
    self._enable_md5_calculate = enable

  @property
  def timeout(self):
    return self._timeout

  @timeout.setter
  def timeout(self, timeout):
    self._timeout = timeout

  @property
  def max_retries(self):
    return self._max_retries

  @max_retries.setter
  def max_retries(self, max_retries):
    self._max_retries = max_retries

  def get_download_base_uri(self):
    return self._build_base_uri(self._enable_cdn_for_download)

  def get_upload_base_uri(self):
    return self._build_base_uri(self._enable_cdn_for_upload)

  def get_base_uri(self):
    return self._build_base_uri(False)

  def _build_base_uri(self, enable_cdn):
    base_uri = str()
    if self._enable_https:
      base_uri += self.HTTPS
    else:
      base_uri += self.HTTP

    if len(self._region_name) > 0:
      base_uri += self._region_name + '-'

    if enable_cdn:
      if self._enable_https:
        base_uri += self.BASE_CDN_HTTPS_HOST
      else:
        base_uri += self.BASE_CDN_HTTP_HOST
    else:
      if self._enable_https:
        base_uri += self.BASE_HTTPS_HOST
      else:
        base_uri += self.BASE_HTTP_HOST
    base_uri += '/'
    return base_uri
