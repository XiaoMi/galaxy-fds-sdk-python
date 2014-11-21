# -*- coding: utf-8 -*-
class Permission(object):
  """Permission is used to manage the permission of FDS."""

  """
  The READ permission: when it applies to buckets it means
  allow the grantee to list the objects in the bucket; when
  it applies to objects it means allow the grantee to read
  the object data and metadata.
  """
  READ = 0x01

  """
  The WRITE permission: when it applies to buckets it means
  allow the grantee to create, overwrite and delete any
  object in the bucket; it is not applicable for objects.
  """
  WRITE = 0x02

  """
  The FULL_CONTROL permission: allows the grantee the READ
  and WRITE permission on the bucket/object.
  """
  FULL_CONTROL = 0xff

  @staticmethod
  def to_string(permission):
    """Convert permission type to string."""

    if permission is Permission.READ:
      return 'READ'
    elif permission is Permission.WRITE:
      return 'WRITE'
    elif permission is Permission.FULL_CONTROL:
      return 'FULL_CONTROL'
    else:
      return ''

  @staticmethod
  def get_value(permission):
    """Get permission type from string."""

    if permission == 'READ':
      return Permission.READ
    elif permission == 'WRITE':
      return Permission.WRITE
    elif permission == 'FULL_CONTROL':
      return Permission.FULL_CONTROL
    else:
      return 0


class UserGroups(object):
  """UserGroups oject is used to manage the user groups."""

  ALL_USERS = 'ALL_USERS'
  AUTHENTICATED_USERS = 'AUTHENTICATED_USERS'


class GrantType(object):
  """GrantType contains user and group."""

  USER = 'USER'
  GROUP = 'GROUP'


class Grantee(dict):
  """Grantee is used to manage the grantee."""

  def __init__(self, id):
    """Initialize the grantee with id."""

    self.id = id

  @property
  def display_name(self):
    return self['displayName']

  @display_name.setter
  def display_name(self, display_name):
    self['displayName'] = display_name

  @property
  def id(self):
    return self['id']

  @id.setter
  def id(self, id):
    self['id'] = id


class Owner(dict):
  """Owner is used to manage the owner of bucket or object."""

  def set_owner_from_json(self, response_content):
    """Set the owner from json data."""

    if response_content != '':
      owner = {}
      if 'id' in response_content.keys():
          owner.id = response_content['id']
      if 'displayName' in response_content.keys():
          owner.display_name = response_content['displayName']
      return owner
    return None

  @property
  def id(self):
    return self.id

  @id.setter
  def id(self, id):
    self['id'] = id

  @property
  def display_name(self):
    return self.display_name

  @display_name.setter
  def display_name(self, display_name):
    self['displayName'] = display_name


class Grant(dict):
  """Grant is the entity to change permission."""

  def __init__(self, grantee, permission):
    """Initialize the grant object with grantee and permission."""

    self.grantee = grantee
    self.type = GrantType.USER
    self.permission = permission
    self.int_perm = permission

  @property
  def permission(self):
    return self['permission']

  @permission.setter
  def permission(self, permission):
    if type(permission) is not str:
        self['permission'] = Permission.to_string(permission)
    else:
        self['permission'] = Permission.get_value(permission)

  @property
  def grantee(self):
    return self['grantee']

  @grantee.setter
  def grantee(self, grantee):
    self['grantee'] = grantee

  @property
  def type(self):
    return self['type']

  @type.setter
  def type(self, type):
    self['type'] = type


class AccessControlList(object):
  """AccessControlList is used to manage all the acl data."""

  def __init__(self):
    """Initialize a dictionary for AccessControlList object."""

    self.acl = {}

  def add_grant(self, grant):
    """Add grant object in acl list."""

    self.acl['%s:%s' % (grant.grantee.id, grant.type)] = grant

  def get_grant_list(self):
    """Get acl list."""

    grants = []
    for k in self.acl:
      grants.append(self.acl[k])
    return grants
