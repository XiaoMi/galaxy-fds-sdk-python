# -*- coding: utf-8 -*-
class QuotaPolicy(object):
  """QuotaPolicy is used to manage the quota policy."""

  @staticmethod
  def get_quota_policy(response_content):
    """Get quota policy from HTTP response."""

    quota = []
    if response_content != '':
      if 'QPS' in response_content.keys():
        quota.qps = response_content['QPS']
      if 'ThroughPut' in response_content.keys():
        quota.thoughPut = response_content['ThoughPut']
      return quota
    return None
