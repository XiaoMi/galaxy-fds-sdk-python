from .permission import Owner


class FDSBucket(object):
  """
  The FDS bucket class.
  """

  def __init__(self, bucket_name, owner=None):
    self.bucket_name = bucket_name
    self.owner = owner
    self.create_date = None

  def __str__(self):
    return self.bucket_name

  @property
  def owner(self):
    return self._owner

  @owner.setter
  def owner(self, json):
    if isinstance(json, dict):
      self._owner = Owner().from_json(json)
    else:
      self._owner = json
