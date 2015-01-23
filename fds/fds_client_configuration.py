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
      enable_https = True):
    self._region_name = region_name
    self._enable_cdn_for_download = enable_cdn_for_download
    self._enable_cdn_for_upload = enable_cdn_for_upload
    self._enable_https = enable_https

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
