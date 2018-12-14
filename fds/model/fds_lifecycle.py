from __future__ import print_function

import json

from fds.galaxy_fds_client_exception import GalaxyFDSClientException


class FDSLifecycleConfig(dict):
  '''
  lifecycle config like this:

  {
   "rules": [
     {
       "id": 0,
       "enabled": true,
       "prefix": "log",
       "actions": {
         "nonCurrentVersionExpiration": {
           "days": 7
         },
         "expiration": {
           "days":30
         }
       }
     },
     {
       "enabled": true,
       "prefix": "images",
       "actions": {
         "nonCurrentVersionExpiration": {
           "days": 7
         },
         "expiration": {
           "days":30
         },
         "abortIncompleteMultipartUpload": {
           "days":7
         }
       }
     }
   ]
 }
  '''

  def __init__(self, json={}):
    dict.__init__(self, json)
    self._rules = []
    for rule in self.get('rules', []):
      self._rules.append(FDSLifecycleRule(rule))
    self['rules'] = self._rules

  @property
  def rules(self):
    return self._rules

  def get_rule_by_prefix(self, prefix):
    for rule in self.rules:
      if rule.prefix == prefix:
        return rule
    return None

  def get_rule_by_object_name(self, object_name, enabled_rule_only=False):
    '''
    Get rule by object name
    :param object_name:
    :param enabled_rule_only:
    :return: Only one rule will return if more than one rules matched.
    '''
    for rule in self.rules:
      if object_name.startswith(rule.prefix) and (rule.enabled or not enabled_rule_only):
        return rule
    return None


class FDSLifecycleRule(dict):
  def __init__(self, json={}):
    dict.__init__(self, json)
    self._actions = {}
    for name, action in self.get('actions', {}).items():
      if name == 'abortIncompleteMultipartUpload':
        self._actions[name] = FDSAbortIncompleteMultipartUpload(action)
      elif name == 'expiration':
        self._actions[name] = FDSExpiration(action)
      elif name == 'nonCurrentVersionExpiration':
        self._actions[name] = FDSNonCurrentVersionExpiration(action)
      elif name == 'lifeCycleStorageClass':
        self._actions[name] = FDSLifecycleStorageClass(action)
      else:
        raise GalaxyFDSClientException("invalid action type: " + name)
    self['actions'] = self._actions

  @property
  def id(self):
    return self.get('id', None)

  @property
  def enabled(self):
    return self.get('enabled', False)

  @enabled.setter
  def enabled(self, enabled):
    self['enabled'] = enabled

  @property
  def prefix(self):
    return self.get('prefix', None)

  @prefix.setter
  def prefix(self, prefix):
    self['prefix'] = prefix

  @property
  def actions(self):
    return self._actions

  def update_action(self, action):
    self.actions[action.name] = action


class FDSExpiration(dict):
  name = 'expiration'

  def __init__(self, json):
    dict.__init__(self, json)

  @property
  def days(self):
    return self.get('days', 0)

  @days.setter
  def days(self, days):
    self['days'] = days


class FDSNonCurrentVersionExpiration(dict):
  name = 'nonCurrentVersionExpiration'

  def __init__(self, json):
    dict.__init__(self, json)

  @property
  def days(self):
    return self.get('days', 0)

  @days.setter
  def days(self, days):
    self['days'] = days


class FDSAbortIncompleteMultipartUpload(dict):
  name = 'abortIncompleteMultipartUpload'

  @property
  def days(self):
    return self.get('days', 0)

  @days.setter
  def days(self, days):
    self['days'] = days

class FDSLifecycleStorageClass(dict):
  name = 'lifeCycleStorageClass'

  @property
  def days(self):
    return self.get('days', 0)

  @days.setter
  def days(self, days):
    self['days'] = days

  @property
  def storage_class(self):
    return self.get('storageClass', "")

  @storage_class.setter
  def storage_class(self, storage_class):
    self['storageClass'] = storage_class

if __name__ == '__main__':
  lifecycle_config = FDSLifecycleConfig()
  rule1 = FDSLifecycleRule()
  rule1.enabled = True
  rule1.prefix = 'test'
  action1 = FDSExpiration({'days': 30})
  rule1.update_action(action1)

  print(json.dumps(rule1, sort_keys=True))

  lifecycle_config.rules.append(rule1)

  print(json.dumps(lifecycle_config, sort_keys=True))

  lifecycle_config.rules.append(rule1)
  print(json.dumps(lifecycle_config, sort_keys=True))

  jsonstr = '''  {
   "rules": [
     {
       "enabled": true,
       "prefix": "log",
       "actions": {
         "nonCurrentVersionExpiration": {
           "days": 7
         },
         "expiration": {
           "days":30.7
         }
       }
     },
     {
       "enabled": true,
       "prefix": "images",
       "actions": {
         "nonCurrentVersionExpiration": {
           "days": 7
         },
         "expiration": {
           "days":30
         },
         "abortIncompleteMultipartUpload": {
           "days":7
         },
         "lifeCycleStorageClass": {
           "days":2,
           "storageClass":"ARCHIVE"
         }
       }
     }
   ]
 }
  '''
  print(jsonstr)
  print(json.dumps(json.loads(jsonstr), sort_keys=True))
  print(json.dumps(FDSLifecycleConfig(json.loads(jsonstr)), sort_keys=True))
