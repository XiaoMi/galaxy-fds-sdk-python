class FDSClientConfiguration(object):
  URI_HTTP = 'http://'

  URI_HTTPS = 'https://'

  URI_CDN = 'cdn'

  URI_SUFFIX = 'fds.api.xiaomi.com'

  URI_NET_SUFFIX = 'fds.api.xiaomi.net'

  URI_CDN_SUFFIX = 'fds.api.mi-img.com'

  def __init__(self, region_name='cnbj0',
               enable_cdn_for_download=True,
               enable_cdn_for_upload=False,
               enable_https=True,
               threshold_size=100 * 1024 * 1024,
               part_size=50 * 1024 * 1024,
               timeout=30,
               max_retries=3,
               endpoint=None):
    """
    :param region_name:
    :param enable_cdn_for_download:
    :param enable_cdn_for_upload:
    :param enable_https:
    :param timeout: connection and read timeout (seconds)
    :param max_retries:
    """
    if region_name is None:
      self._region_name = 'cnbj0'
    else:
      self._region_name = region_name
    self._enable_cdn_for_download = enable_cdn_for_download
    self._enable_cdn_for_upload = enable_cdn_for_upload
    self._enable_https = enable_https
    self._enable_md5_calculate = False
    self._timeout = timeout
    self._max_retries = max_retries
    self._debug = False
    if endpoint is None:
      endpoint = self._region_name + '.' + self.URI_SUFFIX

    self.set_endpoint(endpoint)

    self._threshold_size = threshold_size
    self._part_size = part_size

  def get_threshold_size(self):
    return self._threshold_size

  def set_threshold_size(self, threshold_size):
    self._threshold_size = threshold_size

  def get_part_size(self):
    return self._part_size

  def set_part_size(self, part):
    self._part_size = part

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
    assert endpoint.endswith(self.URI_SUFFIX) or endpoint.endswith(self.URI_NET_SUFFIX)

    self._endpoint = endpoint
    suffix = self._endpoint[-19:]
    i = self._endpoint.index(suffix)
    self._region_name = self._endpoint[0:i]
    self._cdn_endpoint = self.URI_CDN + '.' + self._region_name + '.' + self.URI_CDN_SUFFIX

  def get_download_base_uri(self):
    return self._build_base_uri(self._enable_cdn_for_download)

  def get_upload_base_uri(self):
    return self._build_base_uri(self._enable_cdn_for_upload)

  def get_base_uri(self):
    return self._build_base_uri(False)

  def get_cdn_base_uri(self):
    return self._build_base_uri(True)

  def _build_base_uri(self, enable_cdn):
    base_uri = str()
    if self._enable_https:
      base_uri += self.URI_HTTPS
    else:
      base_uri += self.URI_HTTP

    if enable_cdn:
      base_uri += self._cdn_endpoint
    else:
      base_uri += self._endpoint

    base_uri += '/'
    return base_uri
