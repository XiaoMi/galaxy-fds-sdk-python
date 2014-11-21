# -*- coding: utf-8 -*-

class Error(Exception):
  pass


class GalaxyFDSClientException(Error):
  """GalaxyFDSClientException is used for the exception of FDS."""

  def __init__(self, message):
    self.message = message
