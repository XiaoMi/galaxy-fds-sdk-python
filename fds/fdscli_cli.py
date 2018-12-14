from __future__ import print_function

import concurrent.futures
import errno
import json
import logging
import os
import mimetypes
import sys
from pprint import pprint
from sys import version_info

import fire
import time
from datetime import datetime


from fds import FDSClientConfiguration, GalaxyFDSClient, GalaxyFDSClientException
from fds.fds_cli import multipart_upload_buffer_size, max_upload_retry_time
from fds.model.upload_part_result_list import UploadPartResultList
from fds.model.fds_object_metadata import FDSObjectMetadata
from fds.utils import rfc822_timestamp, file_md5
from fds.auth.common import Common
from fds.model.permission import AccessControlList, UserGroups, Permission, GrantType, Grant, Grantee, Owner


IS_PY3 = version_info[0] >= 3

if not IS_PY3:
  input = raw_input
  
log_format = '%(asctime)-15s [%(filename)s:%(lineno)d] %(message)s'
logging.basicConfig(format=log_format)
logger = logging.getLogger('fds.cli')
logger.setLevel(logging.INFO)

fds_prefix = r'fds://'


def mkdirs(path):
  try:
    if not os.path.isdir(path):
      os.makedirs(path)
  except OSError as exc:
    if exc.errno == errno.EEXIST and os.path.isdir(
        os.path.join(os.path.expanduser("~"), ".config", "xiaomi")):
      pass


class LocalConfig(object):
  def __init__(self):
    self.__config_path = os.path.join(
      os.path.expanduser("~"), ".config", "xiaomi", "config")
    mkdirs(os.path.join(os.path.expanduser("~"), ".config", "xiaomi"))

    self.__data = None

    if not os.path.exists(self.__config_path):
      with open(self.__config_path, 'w+') as f:
        f.writelines("{}")
  
    with open(self.__config_path, 'r+') as f:
      self.__data = json.load(f)

  @property
  def ak(self):
    return self.__data.get('xiaomi_access_key_id')

  @ak.setter
  def ak(self, value):
    if value is not None and value.strip() != '':
      self.__data['xiaomi_access_key_id'] = value
      self.__dump()

  @property
  def sk(self):
    return self.__data.get('xiaomi_secret_access_key')

  @sk.setter
  def sk(self, value):
    if value is not None and value.strip() != '':
      self.__data['xiaomi_secret_access_key'] = value
      self.__dump()

  @property
  def endpoint(self):
    return self.__data.get('xiaomi_fds_endpoint')

  @endpoint.setter
  def endpoint(self, value):
    if value is not None and value.strip() != '':
      self.__data['xiaomi_fds_endpoint'] = value
      self.__dump()

  def __dump(self):
    with open(self.__config_path, 'w') as outfile:
      json.dump(self.__data, outfile,
                sort_keys=True,
                indent=4,
                separators=(',', ': '))


class CLIPrinter(object):
  def __init__(self):
    pass

  @staticmethod
  def done(message):
    print("[done] ", message)

  @staticmethod
  def warn(message):
    print("[warn] ", message)

  @staticmethod
  def fail(message):
    print("[fail] ", message)

  @staticmethod
  def print_bucket(bucket):
    print(bucket.bucket_name)

  @staticmethod
  def wrong_format():
    CLIPrinter.fail("wrong fds url format or local not exists")

  @staticmethod
  def print_object(object_name, metadata, human):
    content_length = int(metadata.metadata['x-xiaomi-meta-content-length'])
    if human == 'k':
      content_length = content_length / 8.0 / 1024
    elif human == 'm':
      content_length = content_length / 8.0 / 1024 / 1024
    elif human == 'g':
      content_length = content_length / 8.0 / 1024 / 1024 / 1024
    print("{}\t{:.2f}{}\t{}".format(metadata.metadata['last-modified'],
                                    content_length,
                                    human,
                                    object_name.encode('utf-8').strip()))

  @staticmethod
  def print_lifecycle(lifecycle):
    for action in lifecycle['rules']:
      pprint(action)
      print('------------------------------------------------')


class FDSURL(object):
  def __init__(self, url):
    if not self.is_fds_url(url):
      CLIPrinter.fail(url + "is not a FDS Bucket URL")

    self.__url = url
    self.__none_fds_prefix_name = url[len(fds_prefix):]

  def is_bucket_url(self):
    """
    fds://bucket_name
    fds://bucket_name/
    """
    tmp = self.__none_fds_prefix_name.split(self.bucket_name() + '/')
    if len(tmp) <= 1 or (len(tmp) == 2 and tmp[1] == ''):
      return True
    return False

  def bucket_name(self):
    return self.__none_fds_prefix_name.split('/')[0]

  def object_name(self):
    if self.is_dir():
      return None
    if self.is_bucket_url():
      return None
    tmp = self.__none_fds_prefix_name.split(self.bucket_name() + '/')
    return tmp[1]

  def file_name(self):
    if not self.is_object_url():
      return None

    return self.__none_fds_prefix_name.split('/')[-1]

  def is_bucket_dir(self):
    """
    fds://bucket_name/
    """
    return self.is_bucket_url() and self.is_dir()

  def is_object_dir(self):
    """
    fds://bucket_name/object_name/
    """
    return not self.is_bucket_url() and self.is_dir()

  def is_dir(self):
    """
    fds://bucket_name/
    fds://bucket_name/object_name/
    """
    return self.__url.endswith("/")

  def object_dir(self):
    if self.is_bucket_url():
      return None
    if not self.is_dir():
      return None
    tmp = self.__none_fds_prefix_name.split(self.bucket_name() + '/')
    return tmp[1]

  def is_object_url(self):
    return not self.is_bucket_url() and not self.is_object_dir()

  @staticmethod
  def is_fds_url(url):
    if url is not None and len(url) > len(fds_prefix):
      return url.startswith(fds_prefix)
    return False

  @property
  def url(self):
    return self.__url


class FDSCli(object):
  """
  Advanced fds cli you deserved!
  """

  def __init__(self, ak=None, sk=None, endpoint=None):
    self._fds_prefix = r'fds://'
    self._fds_prefix_len = len(self._fds_prefix)
    self._local_config = LocalConfig()
    self._ak = self._local_config.ak if ak is None else ak
    if self._ak is None:
      self.config()
    self._sk = self._local_config.sk if sk is None else sk
    if self._sk is None:
      self.config()
    self._endpoint = self._local_config.endpoint if endpoint is None else endpoint
    if self._sk is None:
      self.config()

    logger.debug("endpoint: " + self._endpoint)

    self._fds_config = FDSClientConfiguration(region_name="awsde0",
                                              enable_https=False,
                                              enable_cdn_for_download=False,
                                              enable_cdn_for_upload=False,
                                              endpoint=self._endpoint)
    self._fds = GalaxyFDSClient(access_key=self._ak,
                                access_secret=self._sk,
                                config=self._fds_config)

  def config(self):
    """
    config command configures ak sk and endpoint
    :return:
    """
    default_ak = self._local_config.ak
    default_sk = self._local_config.sk
    default_endpoint = self._local_config.endpoint
    ak = input("enter access key id[default: %s]: " % default_ak)
    if ak == '':
      ak = default_ak
    sk = input("enter secret access key[default: %s]: " % default_sk)
    if sk == '':
      sk = default_sk
    endpoint = input("enter endpoint[default: %s]: " % default_endpoint)
    if endpoint == '':
      endpoint = default_endpoint

    self._local_config.ak = ak
    self._local_config.sk = sk
    self._local_config.endpoint = endpoint

  def mb(self, fds_url):
    """
    create(make) a bucket
    :param fds_url: fds url format like fds://bucket_name_to_make
    """
    url = FDSURL(fds_url)
    if not url.is_bucket_url():
      CLIPrinter.wrong_format()
    bucket_name = url.bucket_name()
    try:
      self._fds.create_bucket(bucket_name)
    except GalaxyFDSClientException as e:
      CLIPrinter.fail(e.message)
      return
    CLIPrinter.done("create bucket [%s]" % bucket_name)

  def rb(self, fds_url, force=False):
    """
    delete(remove) a bucket
    :param fds_url: fds url format like fds://bucket_name_to_delete
    :param force: remove a bucket even if this bucket is not empty
    """
    url = FDSURL(fds_url)
    if not url.is_bucket_url():
      CLIPrinter.wrong_format()
      return
    bucket_name = url.bucket_name()
    if force:
      all_objects = self._fds.list_all_objects(bucket_name, '', '')
      names = []
      try:
        for o in all_objects:
          names.append(o.object_name)
      except GalaxyFDSClientException as e:
        CLIPrinter.warn(e.message)
      try:
        self._fds.delete_objects(bucket_name, names)
      except GalaxyFDSClientException as e:
        CLIPrinter.fail(e.message)
        return
    try:
      self._fds.delete_bucket(bucket_name)
    except GalaxyFDSClientException as e:
      CLIPrinter.fail(e.message)
      return
    CLIPrinter.done("remove bucket [%s]" % bucket_name)

  def rm(self, fds_url):
    """
    delete(remove) a object
    :param fds_url:  fds url format like fds://bucket_name/object_name_to_delete
    """
    url = FDSURL(fds_url)
    bucket_name = url.bucket_name()

    if url.is_bucket_url():
      CLIPrinter.fail("please enter a object resource address to remove")
      return
    object_name = url.object_name()

    try:
      self._fds.delete_object(bucket_name, object_name)
    except GalaxyFDSClientException as e:
      CLIPrinter.fail(e.message)
      return
    CLIPrinter.done("remove object: [%s] in bucket [%s]" % (
      object_name, bucket_name))

  def ls(self, fds_url=None, recursive=False, human='k'):
    """
    list all buckets or objects in a bucket
    :param fds_url: fds url format like fds://bucket
    :param recursive: recursive listing
    """

    if human != 'k' and human != 'm' and human != 'g':
      CLIPrinter.fail("human should be in 'k|m|g'")
      return
    # bucket_url is None means listing all bucket name
    if fds_url is None:
      buckets = None
      try:
        buckets = self._fds.list_authorized_buckets()
      except GalaxyFDSClientException as e:
        CLIPrinter.fail(e.message)
        return
      for bucket in buckets:
        CLIPrinter.print_bucket(bucket)
    else:
      delimiter = "/"
      if recursive:
        delimiter = ""

      url = FDSURL(fds_url)
      bucket_name = url.bucket_name()
      prefix = ''
      if url.is_bucket_url() or url.is_object_dir():
        if url.is_object_dir():
          prefix = url.object_dir()
        results = self._fds.list_all_objects(
          bucket_name, prefix, delimiter)
        try:
          for result in results:
            metadata = self._fds.get_object_metadata(bucket_name, result.object_name)
            CLIPrinter.print_object(result.object_name, metadata, human)
        except GalaxyFDSClientException as e:
          CLIPrinter.fail(e.message)
      else:
        object_name = url.object_name()
        metadata = None
        try:
          metadata = self._fds.get_object_metadata(bucket_name, object_name)
        except GalaxyFDSClientException as e:
          CLIPrinter.fail(e.message)
          return
        if metadata is not None:
          CLIPrinter.print_object(object_name, metadata, human)

  def presigned(self, fds_url, expires=1, cdn=False):
    """
    presigned command generates presigned url for download project
    :param fds_url: format url like fds://bucket/a.txt
    :param expires: expiration time in minutes
    :return: presigned url for downloading
    """

    url = FDSURL(fds_url)
    bucket_name = url.bucket_name()

    if url.is_bucket_url():
      CLIPrinter.fail("%uri is illegal" % fds_url)

    object_name = url.object_name()

    expiration = int(1000 * (float(expires) * 3600 +
                             float((datetime.utcnow() - datetime(1970, 1, 1, 0, 0, 0,
                                                                 0)).total_seconds())))

    try:
      if cdn:
        base_uri = self._fds_config.get_cdn_base_uri()
      else:
        base_uri = self._fds_config.get_base_uri()
      u = self._fds.generate_presigned_uri(base_uri, bucket_name, object_name, expiration)
    except GalaxyFDSClientException as e:
      CLIPrinter.fail(e.message)
      return
    CLIPrinter.done('generated presigned url: ' + u)

  def ttl(self, fds_url):
    """
    ttl command shows the lifecycle information of a bucket or a object
    :param fds_url: format url like fds://bucket/a.txt or fds://bucket/
    """
    url = FDSURL(fds_url)
    bucket_name = url.bucket_name()
    try:
      ttl = self._fds.get_lifecycle_config(bucket_name)
    except GalaxyFDSClientException as e:
      CLIPrinter.fail(e.message)
      return
    if url.is_bucket_url():
      CLIPrinter.print_lifecycle(ttl)
    elif url.is_object_url():
      if not self._fds.does_object_exists(bucket_name, url.object_name()):
        CLIPrinter.fail("object does not exists")
      if url.is_object_dir():
        prefix = url.object_dir()
      else:
        prefix = url.object_name()
      rules = [rule for rule in ttl['rules'] if rule['prefix'] in prefix]
      CLIPrinter.print_lifecycle({"rules": rules})
    else:
      CLIPrinter.wrong_format()

  def cp(self, src, dst, recursive=False, autodetect_mimetype=False):
    """
    cp command do lots of things.
    1. file upload
    2. batch files upload
    3. file download
    4. batch files download
    5. rename object
    6. object copy
    7. batch objects copy
    :param src: source fds url format like fds://bucket
    :param dst: target fds url format like fds://bucket
    :param recursive: recursive listing
    """

    if FDSURL.is_fds_url(src) and FDSURL.is_fds_url(dst):
      src_url = FDSURL(src)
      dst_url = FDSURL(dst)

      if src_url.is_object_url():
        self._cp(src_url, dst_url)
      elif not src_url.is_object_url() and not dst_url.is_object_url():
        self._cp_batch(src_url, dst_url, recursive)
      else:
        CLIPrinter.wrong_format()

    elif FDSURL.is_fds_url(src) and not FDSURL.is_fds_url(dst):
      src_url = FDSURL(src)

      if src_url.is_object_url():
        self._download(src_url, dst)
      elif src_url.is_object_dir() and os.path.isdir(dst):
        self._download_batch(src_url, dst, recursive)
      else:
        CLIPrinter.wrong_format()

    elif not FDSURL.is_fds_url(src) and FDSURL.is_fds_url(dst):
      dst_url = FDSURL(dst)

      if os.path.isfile(src):
        self._upload(src, dst_url, autodetect_mimetype=autodetect_mimetype)
      elif os.path.isdir(src) and not dst_url.is_object_url():
        self._upload_batch(src, dst_url, recursive, autodetect_mimetype=autodetect_mimetype)
      else:
        CLIPrinter.wrong_format()
    else:
      CLIPrinter.fail("don't support copy file from local to local")

  def _cp(self, src_url, dst_url):
    src_bucket_name = src_url.bucket_name()
    src_object_name = src_url.object_name()

    dst_bucket_name = dst_url.bucket_name()

    if dst_url.is_object_url():
      dst_object_name = dst_url.object_name()
    else:
      dst_object_name = src_object_name
    try:
      self._fds.copy_object(src_bucket_name, src_object_name, dst_bucket_name, dst_object_name)
    except GalaxyFDSClientException as e:
      CLIPrinter.fail(e.message)
    CLIPrinter.done(
      "copy %s/%s to %s/%s" % (src_bucket_name, src_object_name, dst_bucket_name, dst_object_name))

  def _cp_batch(self, src_url, dst_url, recursive):
    src_bucket_name = src_url.bucket_name()
    dst_bucket_name = dst_url.bucket_name()

    prefix = ""
    if src_url.is_object_dir():
      prefix = src_url.object_dir()

    delimiter = "/"
    if recursive:
      delimiter = ""

    all_objects = self._fds.list_all_objects(bucket_name=src_bucket_name, prefix=prefix,
                                             delimiter=delimiter)
    try:
      for o in all_objects:
        o_name = o.object_name
        self._fds.copy_object(src_bucket_name, o_name, dst_bucket_name, o_name)
        CLIPrinter.done("copy %s/%s to %s/%s" % (src_bucket_name, o_name, dst_bucket_name, o_name))
    except GalaxyFDSClientException as e:
      CLIPrinter.fail(e.message)

  def _download(self, src_url, dst):
    src_bucket_name = src_url.bucket_name()
    src_object_name = src_url.object_name()

    if os.path.isdir(dst):
      if dst == '.' or dst == '..':
        dst_name = src_url.file_name()
      elif dst.endswith('/'):
        dst_name = dst + src_url.file_name()
      else:
        dst_name = dst + '/' + src_object_name.split('/')[-1]
    else:
      dst_name = dst

    mtime = None
    if os.path.isfile(dst_name):
      local_md5 = file_md5(dst_name)
      remote_md5 = self._fds.get_object_metadata(src_bucket_name, src_object_name).metadata.get(Common.CONTENT_MD5)
      if remote_md5 is not None and local_md5 == remote_md5:
        CLIPrinter.done("download %s/%s to local(skip because of same md5)" % (src_bucket_name, src_object_name))
        return

      mtime = os.path.getmtime(dst_name)

    try:
      fds_object = self._fds.get_object(bucket_name=src_bucket_name, object_name=src_object_name,
                                        stream=True)
    except GalaxyFDSClientException as e:
      CLIPrinter.fail(e.message)
      return
    lm = fds_object.metadata.metadata['last-modified']
    remote_modified = rfc822_timestamp(lm)

    # if last-modified of local file is not less last-modified of remote file, skip
    if mtime is not None and datetime.fromtimestamp(mtime) >= remote_modified:
      CLIPrinter.done("download %s/%s to local(skip because of updated)" % (src_bucket_name, src_object_name))
      return

    length_left = IS_PY3 and sys.maxsize or sys.maxint
    try:
      with open(dst_name, 'wb') as f:
        for chunk in fds_object.stream:
          length = min(length_left, len(chunk))
          f.write(chunk[0:length])
          length_left -= length
          if length_left <= 0:
            break
    except Exception as exception:
      print(exception)
    finally:
      fds_object.stream.close()
    CLIPrinter.done("download %s/%s to local" % (src_bucket_name, src_object_name))

  def _download_batch(self, src_url, dst, recursive):
    src_bucket_name = src_url.bucket_name()

    prefix = ""
    if src_url.is_object_dir():
      prefix = src_url.object_dir()

    delimiter = "/"
    if recursive:
      delimiter = ""

    all_objects = self._fds.list_all_objects(bucket_name=src_bucket_name, prefix=prefix, delimiter=delimiter)
    try:
      for o in all_objects:
        o_name = o.object_name
        url = FDSURL(fds_prefix + src_bucket_name + "/" + o_name)
        if url.is_object_url():
          self._download(url, dst)
    except GalaxyFDSClientException as e:
      CLIPrinter.fail(e.message)

  def _upload(self, filename, dst_url, autodetect_mimetype, sync=False):
    if not os.path.exists(filename):
      CLIPrinter.warn("{} is a bad file".format(filename))
      return
    dst_bucket_name = dst_url.bucket_name()
    if dst_url.is_object_url():
      dst_object_name = dst_url.object_name()
    elif sync:
      dst_object_name = filename[2:]
    elif dst_url.is_object_dir():
      dst_object_name = dst_url.object_dir() + os.path.basename(filename)
    else:
      dst_object_name = os.path.basename(filename)
    try:
      if self._fds.does_object_exists(dst_bucket_name, dst_object_name):
        # check md5 firstly
        metadata = self._fds.get_object_metadata(dst_bucket_name, dst_object_name)
        if metadata.metadata.get(Common.CONTENT_MD5) is not None:
          local_md5 = file_md5(filename)
          if local_md5 == metadata.metadata.get(Common.CONTENT_MD5):
            CLIPrinter.done('upload object %s/%s(skip because of same md5)' % (dst_bucket_name, dst_object_name))
            return

        # check last-modified
        mtime = None
        if os.path.isfile(filename):
          mtime = os.path.getmtime(filename)

        lm = metadata.metadata[Common.LAST_MODIFIED]
        remote_modified = rfc822_timestamp(lm)

        # if last-modified of local file is not less last-modified of remote file, skip
        if mtime is not None and datetime.fromtimestamp(mtime) <= remote_modified:
          CLIPrinter.done('upload object %s/%s(skip because of updated)' % (dst_bucket_name, dst_object_name))
          return
    except Exception as e:
      CLIPrinter.fail(e.message)
      return
    mimetype = None
    if autodetect_mimetype:
      mimetype = mimetypes.guess_type(filename)[0]
    metadata = FDSObjectMetadata()
    if mimetype is not None:
      metadata.add_header(Common.CONTENT_TYPE, mimetype)
    result = None

    with open(filename, "rb") as f:
      file_length = os.path.getsize(filename)
      if file_length < multipart_upload_buffer_size:
        try:
          result = self._fds.put_object(dst_bucket_name, dst_object_name, f, metadata=metadata)
        except GalaxyFDSClientException as e:
          CLIPrinter.fail(e.message)
      else:
        try:
          upload_token = self._fds.init_multipart_upload(dst_bucket_name, dst_object_name)
          part_number = 1
          result_list = []
          while True:
            data = f.read(multipart_upload_buffer_size)
            if len(data) <= 0:
              break
            for i in range(max_upload_retry_time):
              upload_result = None
              try:
                upload_result = self._fds.upload_part(dst_bucket_name, dst_object_name, upload_token.upload_id, part_number, data)
                result_list.append(upload_result)
                break
              except GalaxyFDSClientException as e:
                sleep_seconds = (i + 1) * 10
                CLIPrinter.warn("upload part %d failed, retry after %d seconds" % (
                  part_number, sleep_seconds))
                time.sleep(sleep_seconds)
            part_number = part_number + 1
          upload_part_result = UploadPartResultList({"uploadPartResultList": result_list})
          result = self._fds.complete_multipart_upload(upload_token.bucket_name, upload_token.object_name,
                                                       upload_token.upload_id, metadata,
                                                       json.dumps(upload_part_result))
        except Exception as e:
          self._fds.abort_multipart_upload(dst_bucket_name, dst_object_name, upload_token.upload_id)
          CLIPrinter.fail(e.message)
    if result is not None:
      CLIPrinter.done('upload object %s/%s' % (dst_bucket_name, dst_object_name))
    else:
      CLIPrinter.fail('upload object %s/%s' % (dst_bucket_name, dst_object_name))

  def _upload_batch(self, d, dst_url, recursive, autodetect_mimetype, sync=False):
    for root, dirs, files in os.walk(d):
      relative_dir = os.path.relpath(root, d)
      if relative_dir != '.' and relative_dir != '..' and relative_dir.startswith('.'):
        CLIPrinter.warn('skipping hidden dir ' + relative_dir)
        continue
      for filename in files:
        object_name = os.path.join(root, filename)
        object_name = '/'.join(object_name.split('\\'))
        self._upload(object_name, dst_url, autodetect_mimetype, sync)
      if not recursive:
        break

  def sync(self, src, dst, autodetect_mimetype=False):
    """
    sync command syncs between (local directory and fds) (fds and local directory) (fds and fds)
    :param src: src can be a fds bucket url like fds://bucketname or '.'
    :param dst: src can be a fds bucket url like fds://bucketname or '.'
    :param delete: todo delete target file if source file is deleted
    :param exclude: todo
    :param include: todo
    """
    if FDSURL.is_fds_url(src) and not FDSURL.is_fds_url(dst):
      src_url = FDSURL(src)
      if not src_url.is_bucket_url() or not dst.strip() == '.':
        CLIPrinter.wrong_format()

      src_bucket_name = src_url.bucket_name()
      all_objects = self._fds.list_all_objects(bucket_name=src_bucket_name, prefix='', delimiter='')
      try:
        for o in all_objects:
          o_name = o.object_name
          url = FDSURL(fds_prefix + src_bucket_name + '/' + o_name)
          if '/' not in o_name:
            self._download(url, dst)
          elif url.is_object_url():
            o_file_name = o_name.split('/')[-1]
            o_dir = o_name.split(o_file_name)[0]
            mkdirs(o_dir)
            self._download(url, o_dir)
      except GalaxyFDSClientException as e:
        CLIPrinter.fail(e.message)

    elif not FDSURL.is_fds_url(src) and FDSURL.is_fds_url(dst):
      dst_url = FDSURL(dst)
      if not src.strip() == '.' or not dst_url.is_bucket_url():
        CLIPrinter.wrong_format()
      self._upload_batch(src, dst_url, True, autodetect_mimetype, True)

    elif FDSURL.is_fds_url(src) and FDSURL.is_fds_url(dst):
      self.cp(src, dst)

    else:
      CLIPrinter.wrong_format()

  def make_public(self, url):
    if not FDSURL.is_fds_url(url):
      CLIPrinter.wrong_format()
      return
    url = FDSURL(url)
    if url.is_object_url():
      try:
        self._fds.set_public(url.bucket_name(), url.object_name())
      except GalaxyFDSClientException as e:
        CLIPrinter.fail(e.message)
        return
    elif url.is_bucket_url():
      try:
        acl = AccessControlList()
        grant = Grant(Grantee(UserGroups.ALL_USERS), Permission.READ)
        grant.type = GrantType.GROUP
        acl.add_grant(grant)
        self._fds.set_bucket_acl(url.bucket_name(), acl)
      except GalaxyFDSClientException as e:
        CLIPrinter.fail(e.message)
        return
    else: 
      CLIPrinter.wrong_format()
      return

  def make_outside(self, url, close=False):
    if not FDSURL.is_fds_url(url):
      CLIPrinter.wrong_format()
      return
    url = FDSURL(url)

    if url.is_bucket_url():
      try:
        if close:
          self._fds.set_bucket_outside_access(url.bucket_name(), False)
        else:
          self._fds.set_bucket_outside_access(url.bucket_name(), True)
      except GalaxyFDSClientException as e:
        CLIPrinter.fail(e.message)
        return
    elif url.is_object_url():
      try:
        if close:
          self._fds.set_object_outside_access(url.bucket_name(), url.object_name(), False)
        else:
          self._fds.set_object_outside_access(url.bucket_name(), url.object_name(), True)
      except GalaxyFDSClientException as e:
        CLIPrinter.fail(e.message)
        return
    else:
      CLIPrinter.wrong_format()
      return

  def info(self):
    print("Access Key ID: {}".format(self._local_config.ak))
    print("Access Secret Key: {}".format(self._local_config.sk))
    print("Endpoint: {}".format(self._local_config.endpoint))

def main():
  fire.Fire(FDSCli)


if __name__ == "__main__":
  main()
