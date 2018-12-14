class PutObjectResult(object):
  '''
  The Put Object Result class.
  '''

  def __init__(self, json):
    self.bucket_name = json['bucketName']
    self.object_name = json['objectName']
    self.access_key_id = json['accessKeyId']
    self.signature = json['signature']
    self.expires = json['expires']
    if 'previousVersionId' in json:
      self.previous_version_id = json['previousVersionId']
    else:
      self.previous_version_id = None
