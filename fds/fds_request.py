# wrap the requests library

import requests
from requests.sessions import HTTPAdapter


class FDSRequest:
  def __init__(self, timeout, max_retries):
    self._max_retries = max_retries
    self._timeout = timeout

  def request(self, method, url, kwargs):
    '''
    Constructs a specified session and sends quest.
    Returns :class:`Response <Response>` object.
    '''

    kwargs.setdefault('timeout', self._timeout)
    session = requests.Session()
    session.mount("http://", HTTPAdapter(max_retries=self._max_retries))
    session.mount("https://", HTTPAdapter(max_retries=self._max_retries))
    response = session.request(method=method, url=url, **kwargs)
    # By explicitly closing the session, we avoid leaving sockets open which
    # can trigger a ResourceWarning in some cases, and look like a memory leak
    # in others.
    session.close()
    return response

  def get(self, url, **kwargs):
    kwargs.setdefault('allow_redirects', True)
    return self.request('get', url, kwargs)

  def options(self, url, **kwargs):
    kwargs.setdefault('allow_redirects', True)
    return self.request('options', url, kwargs)

  def head(self, url, **kwargs):
    kwargs.setdefault('allow_redirects', False)
    return self.request('head', url, kwargs)

  def post(self, url, data=None, json=None, **kwargs):
    kwargs['data'] = data
    kwargs['json'] = json
    return self.request('post', url, kwargs)

  def put(self, url, data=None, **kwargs):
    kwargs['data'] = data
    return self.request('put', url, kwargs)

  def patch(self, url, data=None, **kwargs):
    kwargs['data'] = data
    return self.request('patch', url, kwargs)

  def delete(self, url, **kwargs):
    return self.request('delete', url, kwargs)
