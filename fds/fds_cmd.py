#!/usr/bin/env python
"""

Prerequest:
put following json into ~/.config/xiaomi/config
{
...
"xiaomi_access_key_id":"ACCESS_KEY",
"xiaomi_secret_access_key":"SECRET_KEY",
"xiaomi_fds_endpoint":"END_POINT"
, ...
}

Usage Examples:
\t[create bucket]\n\t\tfds -m put -b BUCKET_NAME
\t[list buckets]\n\t\tfds -l
\t[list objects under bucket]\n\t\tfds -l -b BUCKET_NAME
\t[list directory under bucket]\n\t\tfds -L DIR -b BUCKET_NAME
\t[create object under bucket]\n\t\tfds -m put -b BUCKET_NAME -o OBJECT_NAME -d FILE_PATH
\t[create object with pipline]\n\t\tcat file | fds -m put -b BUCKET_NAME -o OBJECT_NAME
\t[generate presigned url for upload, expires in 7 days]\n\t\tfds -p -m put -b BUCKET_NAME -o OBJECT_NAME --expiration '7*24' --metadata 'content-type:application/octet-stream'
\t\tYOUR_PRESIGNED_URL_GENRARTED
\t\t[use presigned url to upload object]\n\t\t\tcurl -v -X PUT -H 'Content-Type:application/octet-stream' 'YOUR_PRESIGNED_URL_GENRARTED' -d 'object content'
\t[generate presigned url for download, expires in 30 min]\n\t\tfds -p -m get -b BUCKET_NAME -o OBJECT_NAME --expiration '0.5'
\t\tYOUR_PRESIGNED_URL_GENRARTED
\t\t[use presigned url to download object]\n\t\t\twget -v 'YOUR_PRESIGNED_URL_GENRARTED'
\t[put bucket acl]\n\t\tfds -m put -b BUCKET_NAME --gratee AUTHENTICATED_USERS --permission READ
"""
from __future__ import print_function
import json
import logging
import os
from os.path import expanduser
import argcomplete
import argparse
import sys
import traceback
from argcomplete.completers import ChoicesCompleter
from datetime import datetime
from time import sleep

from fds import FDSClientConfiguration, GalaxyFDSClient
from fds.model.fds_object_metadata import FDSObjectMetadata
from fds.model.upload_part_result_list import UploadPartResultList
from fds.galaxy_fds_client_exception import GalaxyFDSClientException
from fds.model.permission import Permission
from fds.model.permission import AccessControlList
from fds.model.permission import Grant
from fds.model.permission import Grantee
from fds.model.permission import UserGroups
from fds.model.permission import GrantType

from sys import version_info
IS_PY3 = version_info[0] >= 3

if IS_PY3:
  from urllib.parse import quote
else:
  from urllib import quote

logger = None
access_key = None
secret_key = None
region = ''
fds_config = None
enable_https = True
enable_cdn = False
end_point = None
fds_client = None
presigned_url = False
force_delete = False
gratee = None
permission = None

expiration_in_hour = '1.0'
multipart_upload_threshold_size = 50*1024*1024
multipart_upload_buffer_size = 10*1024*1024
max_upload_retry_time = 5


def print_config(name, value):
  global logger
  if not (logger is None):
    logger.debug('Config param [' + str(name) + '] ' + ' value [' + str(value) + ']')


def read_local_config():
  global logger
  config_dirs = [os.path.join(expanduser("~"), ".config", "xiaomi", "config")
    , os.path.join(expanduser("~"), ".config", "fds", "client.config")];
  for config_dir in config_dirs:
    if not os.path.exists(config_dir):
      if not (logger is None):
        logger.debug("local config not exist [" + str(config_dir) + "]")
    else:
      if not (logger is None):
        logger.debug("use config from [" + str(config_dir) + "]")
      with open(config_dir) as f:
        return json.load(fp=f)
  return {}


def parse_argument(args):
  global method, bucket_name, region, object_name, \
    enable_cdn, enable_https, list_dir, list_objects, \
    data_file, data_dir, start_mark, metadata, length, offset, \
    access_key, secret_key, end_point, presigned_url, expiration_in_hour, \
    force_delete, gratee, permission
  local_config = read_local_config()
  method = args.method
  print_config('method', method)
  if args.bucket:
    bucket_name = args.bucket
  else:
    bucket_name = local_config.get('bucket')
  print_config('bucket name', bucket_name)
  region = local_config.get('region')
  if args.region:
    region = args.region
    if args.end_point:
      end_point = args.end_point
  else:
    if args.end_point:
      end_point = args.end_point
    else:
      end_point = local_config.get('xiaomi_fds_endpoint')
      if end_point is None:
        end_point = local_config.get('end_point')

  print_config('region name', region)
  object_name = args.object
  print_config('object name', object_name)
  enable_cdn = args.CDN
  print_config('cdn enabled', enable_cdn)

  if type(args.https) == str:
    enable_https = args.https.lower() == "true"
  else:
    enable_https = local_config.get("xiaomi_fds_https", True)

  print_config('https enabled', enable_https)
  list_dir = args.list_dir
  print_config('list dir', list_dir)
  list_objects = args.list_objects
  print_config('list objects', list_objects)
  data_file = args.data_file
  print_config('data file', data_file)
  data_dir = args.data_dir
  print_config('data directory', data_dir)
  start_mark = args.start_mark
  print_config('start mark', start_mark)
  metadata = args.metadata
  print_config('meta data', metadata)
  length = args.length
  print_config('length', length)
  offset = args.offset
  print_config('offset', offset)
  print_config('end point', end_point)

  force_delete = args.force_delete
  print_config('force', force_delete)

  if args.ak:
    access_key = args.ak
  else:
    if access_key is None and "XIAOMI_ACCESS_KEY_ID" in os.environ:
      access_key = os.environ["XIAOMI_ACCESS_KEY_ID"]
    if access_key is None:
      access_key = local_config.get('xiaomi_access_key_id')
    if access_key is None:
      access_key = local_config.get('ak')
  print_config('access key', access_key)
  if access_key is None:
    sys.stderr.write('Access key is not set, use command "fds -h" get help')
    sys.stderr.flush()
    exit(1)
  if args.sk:
    secret_key = args.sk
  else:
    if secret_key is None and "XIAOMI_SECRET_ACCESS_KEY" in os.environ:
      secret_key = os.environ["XIAOMI_SECRET_ACCESS_KEY"]
    if secret_key is None:
      secret_key = local_config.get('xiaomi_secret_access_key')
    if secret_key is None:
      secret_key = local_config.get('sk')
  if secret_key is None:
    sys.stderr.write('Secret key is not set, use command "fds -h" get help')
    sys.stderr.flush()
    exit(1)
  presigned_url = args.presigned_url
  print_config('presigned url', presigned_url)
  expiration_in_hour = args.expiration_in_hour
  print_config('expiration in hour', expiration_in_hour)
  gratee = args.gratee
  print_config('gratee', gratee)
  permission = args.permission
  print_config('permission', permission)



def get_buckets(fds_client):
  buckets = fds_client.list_buckets()
  bucket_names = {};
  for i in buckets:
    bucket_names[i.bucket_name] = ''
  authorized_buckets = fds_client.list_authorized_buckets()
  for i in authorized_buckets:
    if i.bucket_name not in bucket_names:
      buckets.append(i);
  return buckets


def list_buckets(fds_client, prefix, start_mark):
  buckets = get_buckets(fds_client)
  for i in buckets:
    if i.bucket_name.startswith(prefix) and (not start_mark or i.bucket_name >= start_mark):
      sys.stdout.write(i.bucket_name + '/')
      sys.stdout.write('\n')


def bucket_name_completer(prefix, parsed_args, **kwargs):
  parse_argument(args=parsed_args)

  if not (access_key is None) and not (secret_key is None) and not (region is None):
    argcomplete.warn(str(enable_https) + ' ' + str(enable_cdn) + ' ' + str(region))
    fds_config = FDSClientConfiguration(region_name=region,
                                        enable_https=enable_https,
                                        enable_cdn_for_download=enable_cdn,
                                        enable_cdn_for_upload=enable_cdn)
    fds_client = GalaxyFDSClient(access_key=access_key,
                                 access_secret=secret_key,
                                 config=fds_config)
    bucket_list = get_buckets(fds_client=fds_client)
    rtn = []
    for i in bucket_list:
      if i.startswith(prefix):
        rtn.append(i)
    return rtn
  return ['a', 'b', 'c']


def check_region(region):
  pass


def check_bucket_name(bucket_name):
  pass


def check_object_name(object_name):
  pass


def check_metadata(metadata):
  pass


def put_directory(data_dir, bucket_name, object_name_prefix, metadata):
  check_bucket_name(bucket_name)
  check_object_name(object_name_prefix)
  check_metadata(metadata)
  # The object name doesn't have starting '/'
  object_name_prefix = object_name_prefix.lstrip('/')
  for root, dirs, files in os.walk(data_dir):
    relative_dir = os.path.relpath(root, data_dir)
    for filename in files:
      data_file = os.path.join(root, filename)
      if filename.startswith('.'):
        logger.warn("object name can't start with '.', skipping " + data_file)
        continue
      object_name = os.path.normpath(os.path.join(object_name_prefix,
                                                  relative_dir,
                                                  filename))
      logger.info('putting %s to %s/%s' % (data_file, bucket_name, object_name))
      put_object(data_file=data_file,
                 bucket_name=bucket_name,
                 object_name=object_name,
                 metadata=metadata)


def put_object(data_file, bucket_name, object_name, metadata):
  check_bucket_name(bucket_name)
  check_object_name(object_name)
  check_metadata(metadata)
  fds_metadata = parse_metadata_from_str(metadata)
  # The object name doesn't have starting '/'
  object_name = object_name.lstrip('/')
  result = None
  if data_file:
    with open(data_file, "rb") as f:
      flen = os.path.getsize(data_file)
      if flen < multipart_upload_threshold_size:
        logger.debug("Put object directly")
        result = fds_client.put_object(bucket_name=bucket_name,
                                       object_name=object_name,
                                       data=f,
                                       metadata=fds_metadata)

      else:
        result = multipart_upload(bucket_name, object_name, fds_metadata, f)
  else:
    result = multipart_upload(bucket_name, object_name, fds_metadata, sys.stdin)
  logger.debug("Upload object success")

  if result:
    logger.info('Put object %s success' % object_name)
  else:
    logger.info('Put object %s failed' % object_name)

def multipart_upload(bucket_name, object_name, metadata, stream):
  upload_token = None
  try:
    logger.debug('Put object in multipart upload mode')
    upload_token = fds_client.init_multipart_upload(bucket_name=bucket_name,
                                                    object_name=object_name)
    logger.debug('Upload id [' + upload_token.upload_id + ']')
    part_number = 1
    upload_list = []
    while True:
      data = stream.read(multipart_upload_buffer_size)
      if len(data) <= 0:
        break
      logger.info("Part %d read %d bytes" % (part_number, len(data)))

      rtn = None
      for i in range(max_upload_retry_time):
        try:
          rtn = fds_client.upload_part(bucket_name=upload_token.bucket_name,
                                       object_name=upload_token.object_name,
                                       upload_id=upload_token.upload_id,
                                       part_number=part_number,
                                       data=data)
          upload_list.append(rtn)
          break
        except:
          sleepSeconds = (i+1)*5
          logger.warning("upload part %d failed, retry after %d seconds" % (part_number, sleepSeconds))
          sleep(sleepSeconds)

      if not rtn:
        raise GalaxyFDSClientException("Upload part %d failed" % part_number)
      part_number += 1

    upload_part_result = UploadPartResultList({"uploadPartResultList": upload_list})
    logger.info("Upload data end, result : %s" % json.dumps(upload_part_result))
    return fds_client.complete_multipart_upload(bucket_name=upload_token.bucket_name,
                                         object_name=upload_token.object_name,
                                         upload_id=upload_token.upload_id,
                                         metadata=metadata,
                                         upload_part_result_list=json.dumps(upload_part_result))
    logger.info("Upload complete")
  except Exception as e:
    try:
      logger.error("Upload id %s will be abort" % upload_token.upload_id)
      fds_client.abort_multipart_upload(bucket_name, object_name, upload_token.upload_id)
    except:
      pass
    raise e

def parse_metadata_from_str(metadata):
  fds_metadata = None
  if metadata:
    fds_metadata = FDSObjectMetadata()
    for i in metadata.split(';'):
      key, value = i.split(':', 1)
      if key and value:
        if key.startswith(FDSObjectMetadata.USER_DEFINED_METADATA_PREFIX):
          fds_metadata.add_user_metadata(key, value)
        else:
          fds_metadata.add_header(key, value)
  return fds_metadata


def get_object(data_file, bucket_name, object_name, metadata, offset, length):
  check_bucket_name(bucket_name)
  check_object_name(object_name)
  fds_object = fds_client.get_object(bucket_name=bucket_name,
                                     object_name=object_name,
                                     position=offset,
                                     stream=True)
  length_left = length
  if length_left == -1:
    length_left = IS_PY3 and sys.maxsize or sys.maxint
  try:
    if data_file:
      with open(data_file, "wb") as f:
        for chunk in fds_object.stream:
          # if isinstance(chunk, bytes):
          #   chunk = chunk.decode(encoding='UTF-8')
          l = min(length_left, len(chunk));
          f.write(chunk[0:l])
          length_left -= l
          if length_left <= 0:
            break
    else:
      for chunk in fds_object.stream:
        # if isinstance(chunk, bytes):
        #   chunk = chunk.decode(encoding='UTF-8')
        l = min(length_left, len(chunk))
        if IS_PY3:
          sys.stdout.buffer.write(chunk[0:l])
        else:
          sys.stdout.write(chunk[0:l])
        length_left -= l
        if length_left <= 0:
          break
      sys.stdout.flush()
  finally:
    fds_object.stream.close()


def post_object(data_file, bucket_name, metadata):
  with open(data_file, 'r') as f:
    fds_object = fds_client.post_object(bucket_name=bucket_name, data=f, metadata=metadata)
    logger.debug('Post object [' + fds_object.object_name + ']')
    sys.stdout.write(fds_object.object_name)


def put_bucket(bucket_name):
  check_bucket_name(bucket_name=bucket_name)
  fds_client.create_bucket(bucket_name)
  sys.stdout.write("Create bucket[%s] success" % bucket_name)


def get_bucket_acl(bucket_name):
  acl = fds_client.get_bucket_acl(bucket_name=bucket_name)
  sys.stdout.write('ACL:\n')
  sys.stdout.write('gratee_id\tgrant_type\tpermission\n')
  for i in acl.get_grant_list():
    sys.stdout.write(str(i.grantee['id']) + '\t' + str(i.type) + '\t' + str(i.permission.to_string()) + '\n')

def put_bucket_acl(bucket_name, gratee_list, permission_list):
  check_bucket_name(bucket_name=bucket_name)
  bucketAcl = AccessControlList()
  for role in gratee_list:
    grant = Grant(Grantee(role), Permission(permission).get_value())
    if role in [UserGroups.ALL_USERS, UserGroups.AUTHENTICATED_USERS]:
      grant.type = GrantType.GROUP
    bucketAcl.add_grant(grant)
  fds_client.set_bucket_acl(bucket_name=bucket_name, acl=bucketAcl)

def delete_object(bucket_name, object_name):
  check_bucket_name(bucket_name=bucket_name)
  check_object_name(object_name=object_name)
  fds_client.delete_object(bucket_name=bucket_name,
                           object_name=object_name)
  logger.info('delete object %s success' % (object_name))

def delete_bucket(bucket_name):
  if fds_client.does_bucket_exist(bucket_name):
    fds_client.delete_bucket(bucket_name=bucket_name)
    logger.info('delete bucket success')
  else:
    logger.info('bucket does not exist')

def delete_bucket_and_objects(bucket_name):
  if fds_client.does_bucket_exist(bucket_name):
    for obj in fds_client.list_all_objects(bucket_name, prefix="", delimiter=""):
      fds_client.delete_object(bucket_name, obj.object_name)
    fds_client.delete_bucket(bucket_name)
    logger.info('delete bucket and objects success')
  else:
    logger.info('bucket does not exist')

def head_object(bucket_name, object_name):
  res = fds_client.does_object_exists(bucket_name=bucket_name,
                                       object_name=object_name)
  if res:
    logger.info('%s exists' % object_name)
  else:
    logger.info('%s does not exists' % object_name)

def head_bucket(bucket_name):
  return fds_client.does_bucket_exist(bucket_name=bucket_name)


def list_directory(bucket_name, object_name_prefix, start_mark):
  if not object_name_prefix:
    object_name_prefix = ''
  path_prefix = object_name_prefix
  if len(path_prefix) > 0 and not path_prefix.endswith('/'):
    path_prefix = path_prefix + '/'
  list_result = fds_client.list_objects(bucket_name=bucket_name,
                                        prefix=path_prefix,
                                        delimiter='/',
                                        )
  if start_mark:
    logger.info('start_marker: ' + start_mark)
    list_result.next_marker = bucket_name + '/' + path_prefix + start_mark
    list_result.is_truncated = True
    list_result = fds_client.list_next_batch_of_objects(list_result)

  prefix_len = len(path_prefix)

  while True:
    for i in list_result.common_prefixes:
      sys.stdout.write(i[prefix_len:])
      sys.stdout.write('\n')
    for i in list_result.objects:
      sys.stdout.write(i.object_name[prefix_len:])
      sys.stdout.write('\n')
    sys.stdout.flush()
    if not list_result.is_truncated:
      break
    list_result = fds_client.list_next_batch_of_objects(list_result)


def list_object(bucket_name, object_name_prefix, start_mark=''):
  list_result = fds_client.list_objects(bucket_name=bucket_name,
                                        prefix=object_name_prefix,
                                        delimiter='')
  if start_mark:
    list_result.is_truncated = True
    list_result.next_marker = bucket_name + '/' + object_name_prefix + start_mark
    list_result = fds_client.list_next_batch_of_objects(list_result)

  for i in list_result.common_prefixes:
    sys.stdout.write(i)
    sys.stdout.write('\n')
  for i in list_result.objects:
    sys.stdout.write(i.object_name)
    sys.stdout.write('\n')
  sys.stdout.flush()
  if list_result.is_truncated:
    sys.stdout.write('...\n')

def main():
  parser = argparse.ArgumentParser(description=__doc__,
                                   formatter_class=argparse.RawDescriptionHelpFormatter,
                                   epilog="Doc - http://docs.api.xiaomi.com/fds/")

  parser.add_argument('-m', '--method',
                      nargs='?',
                      metavar='method',
                      const='put',
                      type=str,
                      dest='method',
                      help='Method of the request. Can be one of put/get/delete/post/head (default: put)'
                      ).completer = ChoicesCompleter(('put', 'get', 'delete', 'post', 'head'))

  parser.add_argument('-b', '--bucket',
                      nargs='?',
                      metavar='bucket',
                      type=str,
                      dest='bucket',
                      help='Name of bucket to operate'
                      ).completer = bucket_name_completer

  parser.add_argument('-o', '--object',
                      nargs='?',
                      metavar='object',
                      type=str,
                      dest='object',
                      help='Name of object to operate'
                      )

  parser.add_argument('-r', '--region',
                      nargs='?',
                      metavar='region',
                      type=str,
                      dest='region',
                      help='Can be one of cnbj0/cnbj1/cnbj2/awsbj0/awsusor0/awssgp0/awsde0 (default: cnbj0)'
                      )

  parser.add_argument('-e', '--end_point',
                      nargs='?',
                      metavar='end point',
                      type=str,
                      dest='end_point',
                      help='can be [cnbj1.fds.api.xiaomi.com] or empty'
                      )

  parser.add_argument('-c', '--CDN',
                      metavar='CDN',
                      action='store_const',
                      const=False,
                      dest='CDN',
                      default=False,
                      help='If toggled, CDN is enabled'
                      )

  parser.add_argument('-p', '--presigned_url',
                      action='store_true',
                      dest='presigned_url',
                      default=False,
                      help='If toggled, generate presigned url'
                      )

  parser.add_argument('--https',
                      metavar='https',
                      nargs='?',
                      dest='https',
                      default=True,
                      help='If toggled, https is enabled'
                      )

  parser.add_argument('--ak',
                      nargs='?',
                      metavar='ACCESS_KEY',
                      dest='ak',
                      help='Specify access key'
                      )

  parser.add_argument('--sk',
                      nargs='?',
                      metavar='SECRET_KEY',
                      dest='sk',
                      help='Specify secret key'
                      )

  parser.add_argument('-L', '--list',
                      nargs='?',
                      metavar='list directory',
                      const='',
                      type=str,
                      dest='list_dir',
                      help='List Bucket/Object under current user')

  parser.add_argument('-l', '--list_objects',
                      nargs='?',
                      metavar='list objects',
                      const='',
                      type=str,
                      dest='list_objects',
                      help='List Bucket/Object under current user')

  parser.add_argument('-d', '--data',
                      nargs='?',
                      metavar='data file',
                      dest='data_file',
                      help='file to be uploaded or stored')

  parser.add_argument('-D', '--directory',
                      nargs='?',
                      metavar='data dir',
                      dest='data_dir',
                      help='directory to be uploaded or stored')

  parser.add_argument('--offset',
                      nargs='?',
                      metavar='offset',
                      type=int,
                      const=0,
                      default=0,
                      dest='offset',
                      help='offset of object to be read')

  parser.add_argument('--length',
                      nargs='?',
                      metavar='length',
                      type=int,
                      dest='length',
                      const=-1,
                      default=-1,
                      help='length of object to be read')

  parser.add_argument('--metadata',
                      nargs='?',
                      metavar='meta data of object to be uploaded',
                      dest='metadata',
                      help='example: "content-type:text/json;x-xiaomi-meta-user-defined:foo"')

  parser.add_argument('--start',
                      nargs='?',
                      metavar='start mark',
                      type=str,
                      dest='start_mark',
                      const=None,
                      default=None,
                      help='used with -l or -L option, returned object name should be *no less* than start mark in dictionary order'
                      )

  parser.add_argument('--debug',
                      metavar='debug',
                      action='store_const',
                      const=True,
                      default=False,
                      dest='debug',
                      help='If toggled, print debug log')

  parser.add_argument('--expiration',
                      nargs='?',
                      type=str,
                      metavar='expiration in hour',
                      default='1.0',
                      dest='expiration_in_hour',
                      help='used with --presigned_url, set expiration of presigned url generated from now on(hour), default to one hour')

  parser.add_argument('--force',
                      action='store_true',
                      dest='force_delete',
                      default=False,
                      help='If toggled, delete bucket and objects')

  group = parser.add_argument_group('acl')
  group.add_argument('--gratee',
                      nargs='+',
                      metavar='user, group, ALL_USERS, AUTHENTICATED_USERS',
                      dest='gratee',
                      help='Add acl to bucket')
  group.add_argument('--permission',
                      nargs='?',
                      metavar="READ, WRITE, READ_OBJECTS, FULL_CONTROL",
                      dest='permission',
                      choices=['READ', 'WRITE', 'READ_OBJECTS', 'FULL_CONTROL'],
                      help='Add acl to bucket')

  argcomplete.autocomplete(parser)

  args = parser.parse_args()

  # set logging
  log_format = '%(asctime)-15s [%(filename)s:%(lineno)d] %(message)s'
  logging.basicConfig(format=log_format)
  global logger
  logger = logging.getLogger('fds.cmd')
  debug_enabled = args.debug

  if debug_enabled:
    logger.setLevel(logging.DEBUG)
  else:
    logger.setLevel(logging.INFO)
  ## read config
  parse_argument(args=args)

  check_region(region=region)
  check_bucket_name(bucket_name=bucket_name)
  global fds_config
  fds_config = FDSClientConfiguration(region_name=region,
                                      enable_https=enable_https,
                                      enable_cdn_for_download=enable_cdn,
                                      enable_cdn_for_upload=enable_cdn)
  global end_point
  if not end_point is None:
    fds_config.set_endpoint(end_point)
  global fds_client
  fds_client = GalaxyFDSClient(access_key=access_key,
                               access_secret=secret_key,
                               config=fds_config)

  global force_delete

  try:
    if presigned_url:
      expiration = int(1000 * (float(eval(expiration_in_hour)) * 3600 +
                               float((datetime.utcnow() - datetime(1970, 1, 1, 0, 0, 0, 0)).total_seconds())))
      meta = parse_metadata_from_str(metadata=metadata)
      content_type = None
      if meta and 'content-type' in meta.metadata:
        content_type = meta.metadata['content-type']
      url = fds_client.generate_presigned_uri(fds_config.get_base_uri(),
                                              bucket_name=bucket_name, object_name=object_name,
                                              expiration=expiration, http_method=method.upper(),
                                              content_type=content_type)
      print(url)
    elif not (list_dir is None):
      if not (bucket_name is None):
        list_directory(bucket_name=bucket_name,
                       object_name_prefix=list_dir, start_mark=start_mark)
      else:
        list_buckets(fds_client=fds_client, prefix=list_dir, start_mark=start_mark)
    elif not (list_objects is None):
      if not (bucket_name is None):
        list_object(bucket_name=bucket_name, object_name_prefix=list_objects, start_mark=start_mark)
      else:
        list_buckets(fds_client=fds_client, prefix=list_objects, start_mark=start_mark)
      pass
    else:
      if method == 'put':
        if object_name:
          if data_dir:
            put_directory(data_dir=data_dir,
                          bucket_name=bucket_name,
                          object_name_prefix=object_name,
                          metadata=metadata)
          else:
            put_object(data_file=data_file,
                       bucket_name=bucket_name,
                       object_name=object_name,
                       metadata=metadata)
        elif gratee and permission:
          put_bucket_acl(bucket_name, gratee, permission)
        else:
          put_bucket(bucket_name)
        pass
      elif method == 'get':
        if object_name:
          get_object(data_file=data_file,
                     bucket_name=bucket_name,
                     object_name=object_name,
                     metadata=metadata,
                     offset=offset,
                     length=length)
        else:
          get_bucket_acl(bucket_name=bucket_name)
        pass
      elif method == 'post':
        post_object(data_file=data_file,
                    bucket_name=bucket_name,
                    metadata=metadata)
        pass
      elif method == 'delete':
        if object_name:
          delete_object(bucket_name=bucket_name,
                        object_name=object_name)
        elif force_delete:
          delete_bucket_and_objects(bucket_name=bucket_name)
        else:
          delete_bucket(bucket_name=bucket_name)
        pass
      elif method == 'head':
        if object_name:
          if not head_object(bucket_name=bucket_name,
                             object_name=object_name):
            exit(1)
        else:
          if not head_bucket(bucket_name=bucket_name):
            exit(1)
      else:
        parser.print_help()

  except Exception as e:
    print(e)
    print("\n")

    ex_type, ex, tb = sys.exc_info()
    traceback.print_tb(tb)

    # sys.stderr.write(str(e))
    # sys.stderr.flush()
    if debug_enabled:
      logger.debug(e, exc_info=True)
    exit(1)


if __name__ == "__main__":
  main()
