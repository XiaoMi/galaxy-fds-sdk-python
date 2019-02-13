from __future__ import print_function

import json


class FDSCORSConfig(dict):
  '''
  cors config like this:

  {
   "rules": [
     {
       "id": "0",
       "allowOrigin":"*.example.com"
     },
     {
       "id": "1",
       "allowOrigin":"*"
     }
   ]
  }
  '''

  def __init__(self, json={}):
    dict.__init__(self, json)
    self._rules = []
    for rule in self.get('rules', []):
      self._rules.append(FDSCORSRule(rule))
    self['rules'] = self._rules

  @property
  def rules(self):
    return self._rules

  def get_rule_by_id(self, id):
    for rule in self.rules:
      if rule.id == id:
        return rule
    return None

class FDSCORSRule(dict):
  def __init__(self, json = {}):
    dict.__init__(self, json)

  @property
  def id(self):
    return self.get('id', None)

  @id.setter
  def id(self, id):
    self['id'] = id

  @property
  def allowOrigin(self):
    return self.get('allowOrigin', None)

  @allowOrigin.setter
  def allowOrigin(self, allowOrigin):
    self['allowOrigin'] = allowOrigin



if __name__ == '__main__':
  cors_config = FDSCORSConfig()
  rule1 = FDSCORSRule()
  rule1.allowOrigin = '*.example.com'

  print(json.dumps(rule1, sort_keys=True))

  cors_config.rules.append(rule1)

  print(json.dumps(cors_config, sort_keys=True))

  cors_config.rules.append(rule1)
  print(json.dumps(cors_config, sort_keys=True))

  jsonstr = '''  {
   "rules": [
       {
         "id": "0",
         "allowOrigin":"*.example.com"
       },
       {
         "id": "1",
         "allowOrigin":"*"
       }
     ]
 }
  '''
  print(jsonstr)
  print(json.dumps(json.loads(jsonstr), sort_keys=True))
  print(json.dumps(FDSCORSConfig(json.loads(jsonstr)), sort_keys=True))
