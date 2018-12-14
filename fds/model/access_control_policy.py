from ..galaxy_fds_client_exception import GalaxyFDSClientException


class AccessControlPolicy(dict):
  '''
  The access control policy class.
  '''

  def __init__(self, json):
    '''
    Construct access control policy object from json.
    '''
    if json is not None:
      if 'owner' in json.keys():
        self.owner = json['owner']
      else:
        self.owner = None
      if 'accessControlList' in json.keys():
        self.access_control_list = json['accessControlList']
      else:
        self.access_control_list = None
    else:
      raise GalaxyFDSClientException("Json data cannot be None")

  @property
  def owner(self):
    return self.owner

  @owner.setter
  def owner(self, owner):
    self['owner'] = owner

  @property
  def access_control_list(self):
    return self.access_control_list

  @access_control_list.setter
  def access_control_list(self, access_control_list):
    self['accessControlList'] = access_control_list
