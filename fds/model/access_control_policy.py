# -*- coding: utf-8 -*-
class AccessControlPolicy(dict):
  """AccessControlPolicy is used for access control of FDS."""

  @staticmethod
  def get_access_control_policy(response_content):
    """Get the policy of access control from response."""

    if response_content != '':
      acl = AccessControlPolicy()
      if 'owner' in response_content.keys():
        acl.owner = response_content['owner']
      if 'accessControlList' in response_content.keys():
        acl.access_control_list = response_content['accessControlList']
      return acl
    return None

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
