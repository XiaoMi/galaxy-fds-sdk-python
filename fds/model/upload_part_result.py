class UploadPartResult(dict):
  """
  The Upload Part Result class.
  """

  def __init__(self, json):
    self.partNumber = json['partNumber']
    self.etag = json['etag']
    self.partSize = json['partSize']

  @property
  def partNumber(self):
    return self.partNumber

  @partNumber.setter
  def partNumber(self, part_number):
    self['partNumber'] = part_number

  @property
  def etag(self):
    return self.etag

  @etag.setter
  def etag(self, etag):
    self['etag'] = etag

  @property
  def partSize(self):
    return self.partSize

  @partSize.setter
  def partSize(self, part_size):
    self['partSize'] = part_size
