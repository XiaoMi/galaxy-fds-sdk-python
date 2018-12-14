class TimestampAntiStealingLinkConfig(dict):
  def __init__(self, json):
    if json is not None:
      if 'enabled' in json.keys():
        self.enabled = json['enabled']
      else:
        self.enabled = None
      if 'primaryKey' in json.keys():
        self.primary_key = json['primaryKey']
      else:
        self.primary_key = None
      if 'secondaryKey' in json.keys():
        self.secondary_key = json['secondaryKey']
      else:
        self.secondary_key = None
    else:
      raise GalaxyFDSClientException("Json data cannot be None")

  @property
  def enabled(self):
    return self['enabled']

  @enabled.setter
  def enabled(self, enabled):
    self['enabled'] = enabled

  @property
  def primary_key(self):
    return self['primaryKey']

  @primary_key.setter
  def primary_key(self, primary_key):
    self['primaryKey'] = primary_key

  @property
  def secondary_key(self):
    return self['secondaryKey']

  @secondary_key.setter
  def secondary_key(self, secondary_key):
    self['secondaryKey'] = secondary_key
