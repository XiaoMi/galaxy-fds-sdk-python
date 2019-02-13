from ..galaxy_fds_client_exception import GalaxyFDSClientException


class ListDomainMappingsResult(object):
  '''
  The List Domain Mappings Result class:
  '''

  def __init__(self, json):
    if json is not None:
      if 'domainMappings' in json.keys():
        self.domain_mappings = json['domainMappings']
      else:
        self.domain_mappings = None
    else:
      raise GalaxyFDSClientException("Json data cannot be None")

