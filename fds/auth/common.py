class Common(object):
  XIAOMI_HEADER_PREFIX = "x-xiaomi-"
  XIAOMI_HEADER_DATE = "x-xiaomi-date"

  GALAXY_ACCESS_KEY_ID = "GalaxyAccessKeyId"
  SIGNATURE = "Signature"
  EXPIRES = "Expires"

  AUTHORIZATION = "authorization"
  CONTENT_MD5 = "content-md5"
  CONTENT_TYPE = "content-type"
  DATE = "date"
  RANGE = 'range'

  REQUEST_TIME_LIMIT = 900000  # 15min

  CACHE_CONTROL = "cache-control"
  CONTENT_ENCODING = "content-encoding"
  CONTENT_LENGTH = "content-length"
  LAST_MODIFIED = "last-modified"
  LAST_CHECKED = "last-checked"
  UPLOAD_TIME = "upload-time"
  CONTENT_RANGE = "content-range"
  EXPIRATION_TIME = "expiration-time"
  OBJECT_OWNER_ID = "object-owner-id"
  FILE_MODE = "file-mode"
  MULITPART_UPLOAD_MODE = XIAOMI_HEADER_PREFIX + "multipart-upload-mode"
  PREVIOUS_VERSION_ID = "pre-version-id"
  SERVER_SIDE_ENCRYPTION = XIAOMI_HEADER_PREFIX + "server-side-encryption"
  STORAGE_CLASS = XIAOMI_HEADER_PREFIX + "storage-class"

  DEFAULT_FDS_SERVICE_BASE_URI = "http://files.fds.api.xiaomi.com/"
  DEFAULT_CDN_SERVICE_URI = "http://cdn.fds.api.xiaomi.com/"
