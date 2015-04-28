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

  def __init__(self):
    self.metadata = {}

  def add_header(self, key, value):
    self._check_metadata(key)
    self.metadata.update({key: value})

  def add_user_metadata(self, key, value):
    self._check_metadata(key)
    self.metadata.update({key: value})

  def _check_metadata(self, key):
    is_valid = key.startswith(self.USER_DEFINED_METADATA_PREFIX)

    if key in self.PRE_DEFINED_METADATA:
      is_valid = True

    if not is_valid:
      raise GalaxyFDSClientException("Invalid metadata: " + key)


