class Error(Exception):
  pass


class GalaxyFDSClientException(Error):
  def __init__(self, message):
    self.message = message

  def __str__(self):
    if self.message:
      return super.__str__(self) + ": " + str(self.message)
    return super.__str__(self)
