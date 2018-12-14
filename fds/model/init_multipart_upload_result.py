class InitMultipartUploadResult(object):
  """
  The Init Multipart Upload Result class:
  """

  def __init__(self, json):
    self.bucket_name = json['bucketName']
    self.object_name = json['objectName']
    self.upload_id = json['uploadId']
