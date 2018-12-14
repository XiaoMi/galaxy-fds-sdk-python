from sys import version_info

IS_PY3 = version_info[0] >= 3

if IS_PY3:
  pass
else:
  pass


class FDSObject(object):
  '''
  The FDS Object class.
  '''

  def __init__(self):
    self.summary = None
    self.metadata = None
    self.stream = None

  def get_next_chunk_as_string(self, encoding="UTF-8"):
    if IS_PY3:
      return next(self.stream).decode(encoding=encoding)
    else:
      return self.stream.next()
