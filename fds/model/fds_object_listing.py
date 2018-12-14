from .fds_object_summary import FDSObjectSummary
from .permission import Owner


class FDSObjectListing(dict):
  '''
  The FDS Object Listing class.
  '''

  def __init__(self, json):
    dict.__init__(self, json)
    self._objects = []
    for obj in self['objects']:
      summary = FDSObjectSummary()
      summary.bucket_name = self['name']
      summary.object_name = obj['name']
      summary.owner = Owner().from_json(obj['owner'])
      summary.size = obj['size']
      self._objects.append(summary)

  def __str__(self):
    return str(map(lambda x: x.object_name, self._objects))

  @property
  def prefix(self):
    return self['prefix']

  @prefix.setter
  def prefix(self, prefix):
    self['prefix'] = prefix

  @property
  def delimiter(self):
    return self['delimiter'];

  @delimiter.setter
  def delimiter(self, delimiter):
    self['delimiter'] = delimiter

  @property
  def marker(self):
    return self['marker']

  @marker.setter
  def marker(self, marker):
    self['marker'] = marker

  @property
  def next_marker(self):
    return self['nextMarker']

  @next_marker.setter
  def next_marker(self, next_marker):
    self['nextMarker'] = next_marker

  @property
  def bucket_name(self):
    return self['name']

  @bucket_name.setter
  def bucket_name(self, bucket_name):
    self['name'] = bucket_name

  @property
  def delimiter(self):
    return self['delimiter']

  @delimiter.setter
  def delimiter(self, delimiter):
    self['delimiter'] = delimiter

  @property
  def max_keys(self):
    return self['maxKeys']

  @max_keys.setter
  def max_keys(self, max_keys):
    self['maxKeys'] = max_keys

  @property
  def objects(self):
    return self._objects

  @objects.setter
  def objects(self, objects):
    objs = []
    for x in objects:
      if isinstance(x, FDSObjectSummary):
        raise TypeError("Parameter should be a list of FDSObjectSummary")
      objs.append(x)
    self._objects = objs

  @property
  def common_prefixes(self):
    return self['commonPrefixes']

  @common_prefixes.setter
  def common_prefixes(self, common_prefixes):
    self['commonPrefixes'] = common_prefixes

  @property
  def is_truncated(self):
    return self['truncated']

  @is_truncated.setter
  def is_truncated(self, is_truncated):
    self['truncated'] = is_truncated
