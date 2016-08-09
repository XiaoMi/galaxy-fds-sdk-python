class FDSClientConfiguration(object):

  URI_HTTP = 'http://'

  URI_HTTPS = 'https://'

  URI_CDN = 'cdn'

  URI_SUFFIX = 'fds.api.xiaomi.com'

  URI_CDN_SUFFIX = 'fds.api.mi-img.com'

  def __init__(self, region_name = 'cnbj0',
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
    self._endpoint = ''

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

  def set_endpoint(self, endpoint):
    self._endpoint = endpoint

  def get_download_base_uri(self):
    return self._build_base_uri(self._enable_cdn_for_download)

  def get_upload_base_uri(self):
    return self._build_base_uri(self._enable_cdn_for_upload)

  def get_base_uri(self):
    return self._build_base_uri(False)

  def _build_base_uri(self, enable_cdn):
    base_uri = str()
    if self._enable_https:
      base_uri += self.URI_HTTPS
    else:
      base_uri += self.URI_HTTP

    region = self._region_name
    if not region:
      region = "cnbj0"
    if self._endpoint:
      base_uri += self._endpoint
    elif enable_cdn:
      base_uri += self.URI_CDN + '.' + region + '.' + self.URI_CDN_SUFFIX
    else:
      base_uri += region + '.' + self.URI_SUFFIX

    base_uri += '/'
    return base_uri
