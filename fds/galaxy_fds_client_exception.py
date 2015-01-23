class Error(Exception):
  pass

class GalaxyFDSClientException(Error):
  def __init__(self, message):
    self.message = message
