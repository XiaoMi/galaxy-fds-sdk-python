class AccessLogConfig(dict):
  '''
  The Access Log Config Class:
  '''

  def __init__(self, json):
    if 'bucketName' in json.keys():
      self.bucketName = json['bucketName']
    if 'enabled' in json.keys():
      self.enabled = json['enabled']
    if 'logBucketName' in json.keys():
      self.logBucketName = json['logBucketName']
    if 'logPrefix' in json.keys():
      self.logPrefix = json['logPrefix']
    if 'cdnEnabled' in json.keys():
      self.cdnEnabled = json['cdnEnabled']
    if 'cdnLogPrefix' in json.keys():
      self.cdnLogPrefix = json['cdnLogPrefix']

  @property
  def cdnEnabled(self):
    return self.cdnEnabled

  @cdnEnabled.setter
  def cdnEnabled(self, cdnEnabled):
    self['cdnEnabled'] = cdnEnabled

  @property
  def logPrefix(self):
    return self.logPrefix

  @logPrefix.setter
  def logPrefix(self, logPrefix):
    self['logPrefix'] = logPrefix

  @property
  def enabled(self):
    return self.enabled

  @enabled.setter
  def enabled(self, enabled):
    self['enabled'] = enabled

  @property
  def logBucketName(self):
    return self.logBucketName

  @logBucketName.setter
  def logBucketName(self, logBucketName):
    self['logBucketName'] = logBucketName

  @property
  def bucketName(self):
    return self.bucketName

  @bucketName.setter
  def bucketName(self, bucketName):
    self['bucketName'] = bucketName

  @property
  def cdnLogPrefix(self):
    return self.cdnLogPrefix

  @cdnLogPrefix.setter
  def cdnLogPrefix(self, cdnLogPrefix):
    self['cdnLogPrefix'] = cdnLogPrefix
