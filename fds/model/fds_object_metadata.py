from fds.auth.common import Common

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
  metadata = {}

  def add_header(self, key, value):
    self.metadata.update({key: value})

  def add_user_metadata(self, key, value):
    self.metadata.update({key: value})


