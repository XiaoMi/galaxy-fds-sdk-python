from fds.auth.common import Common
from fds.galaxy_fds_client_exception import GalaxyFDSClientException


class FDSObjectMetadata(object):
  '''
  The FDS object metadata class.
  '''
  USER_DEFINED_METADATA_PREFIX = "x-xiaomi-meta-"

  PRE_DEFINED_METADATA = [
    Common.CACHE_CONTROL,
    Common.CONTENT_ENCODING,
    Common.CONTENT_LENGTH,
    Common.CONTENT_MD5,
    Common.CONTENT_TYPE
  ]

  IMAGE_MIME = { 'png': "image/png", \
                 'gif': "image/gif", \
                 'jpg': "image/jpeg", \
                 'jpeg': "image/jpeg" }

  def __init__(self, **kwargs):
    if len(kwargs) > 0:
      for key in kwargs.keys():
        self._check_metadata(key)
    self.metadata = kwargs

  def __repr__(self):
    return "<FDSObjectMetadata %s>" % str(self.metadata)

  def set_image_mime(self, ext):
    mime = self.IMAGE_MIME.get(ext)
    if mime is None:
      raise GalaxyFDSClientException("Invalid ext: %s. only jpg/jpeg/gif/png" % ext)
    self.metadata[Common.CONTENT_TYPE] = mime
    return self

  def add_header(self, key, value):
    self._check_metadata(key)
    self.metadata.update({key: value})
    return self

  def add_user_metadata(self, key, value):
    self._check_metadata(key)
    self.metadata.update({key: value})
    return self

  def _check_metadata(self, key):
    if key in self.PRE_DEFINED_METADATA:
      return True
    if key.startswith(self.USER_DEFINED_METADATA_PREFIX):
      return True
    raise GalaxyFDSClientException("Invalid metadata: %s" % key)

