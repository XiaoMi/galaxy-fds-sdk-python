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
\t[delete object]\n\t\tfds -m delete -b BUCKET_NAME -o OBJECT_NAME [--disable_trash]
\t[delete objects]\n\t\tfds -m delete -b BUCKET_NAME --object_prefix=OBJECT_NAME_PREFIX [--disable_trash]
\t[delete empty bucket]\n\t\tfds -m delete -b BUCKET_NAME
\t[delete bucket with object]\n\t\tfds -m delete -b BUCKET_NAME --force
\t[download object]\n\t\tfds -m get -b BUCKET_NAME -o OBJECT_NAME -d OUTPUT_FILE_NAME
\t[download directory(object preifx) recursively]\n\t\tfds -m get -b BUCKET_NAME --P OBJECT_PREFIX -D OUTPUT_DIRECTORY -R
\t[download all objects under a bucket]\n\t\tfds -m get -b BUCKET_NAME -P / -D OUTPUT_DIRECTORY -R
\t[copy src_object from src_bucket to dst_bucket and rename it to dst_object]\n\t\tfds -m put -srcb SRC_BUCKET_NAME -srco SRC_OBJECT_NAME -dstb DST_BUCKET_NAME -dsto DST_OBJECT_NAME
"""
from __future__ import print_function

import json
import logging
import os
import sys
import traceback
from os.path import expanduser
from sys import version_info

import argcomplete
import argparse
from argcomplete.completers import ChoicesCompleter
from datetime import datetime
from time import sleep

from fds import FDSClientConfiguration, GalaxyFDSClient
from fds.galaxy_fds_client_exception import GalaxyFDSClientException
from fds.model.fds_lifecycle import FDSLifecycleConfig, FDSLifecycleRule
from fds.model.fds_cors import FDSCORSConfig, FDSCORSRule
from fds.model.fds_object_metadata import FDSObjectMetadata
from fds.model.permission import AccessControlList
from fds.model.permission import Grant
from fds.model.permission import GrantType
from fds.model.permission import Grantee
from fds.model.permission import Permission
from fds.model.permission import UserGroups
from fds.model.upload_part_result_list import UploadPartResultList

IS_PY3 = version_info[0] >= 3

if IS_PY3:
  pass
else:
  pass

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
disable_trash = False
object_prefix = None
gratee = None
permission = None
is_public = False
lifecycle = None
lifecycle_rule = None
cors=None
cors_rule=None
recursive = False
webp_quality = None
gif_extract_type = None
restore_archive = False
is_archive = False
list_trash = False

expiration_in_hour = '1.0'
multipart_upload_threshold_size = 50 * 1024 * 1024
multipart_upload_buffer_size = 10 * 1024 * 1024
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
    force_delete, gratee, permission, disable_trash, object_prefix, lifecycle, lifecycle_rule, \
    recursive, dst_bucket_name, dst_object_name, src_bucket_name, src_object_name, webp_quality, gif_extract_type, cors, cors_rule,\
    restore_archive, is_archive, list_trash, is_public
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

  disable_trash = args.disable_trash
  print_config('disable_trash', disable_trash)

  object_prefix = args.object_prefix

  print_config('object_prefix', object_prefix)

  webp_quality = args.webp_quality
  print_config('webp_quality', webp_quality)

  gif_extract_type = args.gif_extract_type
  print_config('gif_extract_type', gif_extract_type)

  restore_archive = args.restore_archive
  print_config('restore archived object', restore_archive)

  is_archive = args.is_archive
  print_config('is_archive', is_archive)

  list_trash = args.list_trash
  print_config('list_trash', list_trash)

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
  is_public = args.is_public
  print_config('is_public', is_public)

  src_bucket_name = args.src_bucket_name
  print_config('src_bucket_name', src_bucket_name)
  src_object_name = args.src_object_name
  print_config('src_object_name', src_object_name)
  dst_bucket_name = args.dst_bucket_name
  print_config('dst_bucket_name', dst_bucket_name)
  dst_object_name = args.dst_object_name
  print_config('dst_object_name', dst_object_name)

  lifecycle = args.lifecycle
  print_config('lifecycle', lifecycle)
  lifecycle_rule = args.lifecycle_rule
  print_config('lifecycle_rule', lifecycle_rule)
  cors = args.cors
  print_config('cors', cors)
  cors_rule = args.cors_rule
  print_config('cors_rule', cors_rule)
  recursive = args.recursive
  print_config('recursive', recursive)


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
      if '/' in filename or '\\' in filename:
        logger.warn("object name can't contain '/' or '\\', skipping " + data_file)
        continue
      object_name = os.path.normpath(os.path.join(object_name_prefix,
                                                  relative_dir,
                                                  filename))
      object_name = '/'.join(object_name.split('\\'))
      logger.info('putting %s to %s/%s' % (data_file, bucket_name, object_name))
      put_object(data_file=data_file,
                 bucket_name=bucket_name,
                 object_name=object_name,
                 metadata=metadata)


def put_object(data_file, bucket_name, object_name, metadata, is_archive=False):
  check_bucket_name(bucket_name)
  check_object_name(object_name)
  check_metadata(metadata)
  fds_metadata = parse_metadata_from_str(metadata)
  # The object name doesn't have starting '/'
  object_name = object_name.lstrip('/')
  result = None
  if data_file:
    with open(data_file, "rb") as f:
      result = fds_client.put_object(bucket_name, object_name, f, fds_metadata, is_archive=is_archive)
  else:
    result = fds_client.put_object(bucket_name, object_name, sys.stdin, fds_metadata, is_archive=is_archive)
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
          sleepSeconds = (i + 1) * 5
          logger.warning(
            "upload part %d failed, retry after %d seconds" % (part_number, sleepSeconds))
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
                                                upload_part_result_list=json.dumps(
                                                  upload_part_result))
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


def get_object(data_file, bucket_name, object_name, metadata, offset, length,
    webp_quality=False, gif_extract_type=False, is_archive=False):
  check_bucket_name(bucket_name)
  check_object_name(object_name)
  if webp_quality:
    fds_object = fds_client._get_webp_(bucket_name=bucket_name,
                                         object_name=object_name,
                                         quality=webp_quality)
    length = -1
    offset = 0
  elif gif_extract_type:
    fds_object = fds_client._get_extracted_gif_(bucket_name=bucket_name,
                                                object_name=object_name,
                                                type=gif_extract_type)
    length = -1
    offset = 0
  else:
    fds_object = fds_client.get_object(bucket_name=bucket_name,
                                       object_name=object_name,
                                       position=offset,
                                       stream=True,
                                       is_archive=is_archive)

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


def download_directory(bucket_name, object_prefix, data_dir, recursive):
  def mkdirs(path):
    if not os.path.isdir(path):
      os.makedirs(path)

  delimiter = not recursive and '/' or ''

  if not object_prefix.endswith('/'):
    sys.stderr.write('Object prefix must endswith /')
    sys.stderr.flush()
    return

  if not data_dir:
    data_dir = './'

  if not data_dir.endswith('/'):
    data_dir += '/'

  if object_prefix == '/':  # download all objects under bucket
    objects_list = fds_client.list_objects(bucket_name, prefix='', delimiter=delimiter)
  else:
    objects_list = fds_client.list_objects(bucket_name, prefix=object_prefix, delimiter=delimiter)
  # print(objects_list.objects)
  while True:
    for obj in objects_list.objects:
      if obj.object_name.endswith('/'):
        mkdirs(data_dir + obj.object_name)
      else:
        if '/' in obj.object_name:
          mkdirs(data_dir + obj.object_name[:obj.object_name.rfind('/')])
        obj_path = data_dir + obj.object_name
        if os.path.exists(obj_path) and obj.size == os.path.getsize(obj_path):
          logger.debug("[%s/%s] is already downloaded" % (bucket_name, obj.object_name))
        else:
          get_object(data_dir + obj.object_name, bucket_name, obj.object_name, None, 0, -1)
          logger.debug("Download [%s/%s] success" % (bucket_name, obj.object_name))
    for prefix in objects_list.common_prefixes:
      mkdirs(data_dir + prefix)
    if objects_list.is_truncated:
      objects_list = fds_client.list_next_batch_of_objects(objects_list)
    else:
      break

  sys.stdout.write("Downdoad directory[%s] success" % object_prefix)
  sys.stdout.flush()


def put_bucket(bucket_name):
  check_bucket_name(bucket_name=bucket_name)
  fds_client.create_bucket(bucket_name)
  sys.stdout.write("Create bucket[%s] success" % bucket_name)


def get_bucket_acl(bucket_name):
  acl = fds_client.get_bucket_acl(bucket_name=bucket_name)
  sys.stdout.write('ACL:\n')
  sys.stdout.write('gratee_id\tgrant_type\tpermission\n')
  for i in acl.get_grant_list():
    sys.stdout.write(
      str(i.grantee['id']) + '\t' + str(i.type) + '\t' + str(i.permission.to_string()) + '\n')


def put_bucket_acl(bucket_name, gratee_list, permission_list):
  check_bucket_name(bucket_name=bucket_name)
  bucketAcl = AccessControlList()
  for role in gratee_list:
    grant = Grant(Grantee(role), Permission(permission_list).get_value())
    if role in [UserGroups.ALL_USERS, UserGroups.AUTHENTICATED_USERS]:
      grant.type = GrantType.GROUP
    bucketAcl.add_grant(grant)
  fds_client.set_bucket_acl(bucket_name=bucket_name, acl=bucketAcl)


def delete_bucket_acl(bucket_name, gratee_list, permission_list):
  check_bucket_name(bucket_name=bucket_name)
  bucketAcl = AccessControlList()
  for role in gratee_list:
    grant = Grant(Grantee(role), Permission(permission_list).get_value())
    if role in [UserGroups.ALL_USERS, UserGroups.AUTHENTICATED_USERS]:
      grant.type = GrantType.GROUP
    bucketAcl.add_grant(grant)
  fds_client.delete_bucket_acl(bucket_name=bucket_name, acl=bucketAcl)


def delete_object_acl(bucket_name, object_name, gratee_list, permission_list, is_archive=False):
  check_bucket_name(bucket_name)
  check_bucket_name(object_name)
  object_acl = AccessControlList()
  for role in gratee_list:
    grant = Grant(Grantee(role), Permission(permission_list).get_value())
    if role in [UserGroups.ALL_USERS, UserGroups.AUTHENTICATED_USERS]:
      grant.type = GrantType.GROUP
    object_acl.add_grant(grant)
  fds_client.delete_object_acl(bucket_name, object_name, object_acl, is_archive=is_archive)


def get_object_acl(bucket_name, object_name, is_archive=False):
  acl = fds_client.get_object_acl(bucket_name=bucket_name, object_name=object_name, is_archive=is_archive)
  sys.stdout.write('ACL:\n')
  sys.stdout.write('gratee_id\tgrant_type\tpermission\n')
  for i in acl.get_grant_list():
    sys.stdout.write(str(i.grantee['id']) + '\t' + str(i.type) + '\t' + str(i.permission.to_string()) + '\n')


def put_object_acl(bucket_name, object_name, gratee_list, permission_list, is_archive=False):
  check_bucket_name(bucket_name=bucket_name)
  check_object_name(object_name=object_name)
  object_acl = AccessControlList()
  for role in gratee_list:
    grant = Grant(Grantee(role), Permission(permission_list).get_value())
    if role in [UserGroups.ALL_USERS, UserGroups.AUTHENTICATED_USERS]:
      grant.type = GrantType.GROUP
    object_acl.add_grant(grant)
  fds_client.set_object_acl(bucket_name, object_name, object_acl, is_archive=is_archive)
  logger.info('set [%s/%s] acl success', bucket_name, object_name)

def set_public(bucket_name, object_name=None, is_archive=False):
  check_bucket_name(bucket_name)
  fds_client.set_public(bucket_name, object_name=object_name, is_archive=is_archive)
  if object_name:
    if is_archive:
      sys.stdout.write('set archive %s/%s public success' % (bucket_name, object_name))
    else:
      sys.stdout.write('set object %s/%s public success' % (bucket_name, object_name))
  else:
    sys.stdout.write('set bucket %s public success' % bucket_name)
  sys.stdout.flush()

def restore_archived_object(bucket_name, object_name):
  check_bucket_name(bucket_name=bucket_name)
  check_object_name(object_name=object_name)
  fds_client._restore_archived_object_(bucket_name, object_name)
  logger.info('restore archived object [%s/%s] success; this may takes several hours', bucket_name, object_name)

def put_bucket_lifecycle_config(bucket_name, lifecycle):
  check_bucket_name(bucket_name)
  lifecycle = FDSLifecycleConfig(json.loads(lifecycle))
  fds_client.update_lifecycle_config(bucket_name, lifecycle)
  sys.stdout.write("put [%s] lifecycle config success" % bucket_name)
  sys.stdout.flush()


def put_bucket_cors_config(bucket_name, cors):
  check_bucket_name(bucket_name)
  cors = FDSCORSConfig(json.loads(cors))
  fds_client.update_cors_config(bucket_name, cors)
  sys.stdout.write("put [%s] cors config success" % bucket_name)
  sys.stdout.flush()


def put_bucket_lifecycle_rule(bucket_name, lifecycle_rule):
  check_bucket_name(bucket_name)
  rule = FDSLifecycleRule(json.loads(lifecycle_rule))
  fds_client.update_lifecycle_rule(bucket_name, rule)
  sys.stdout.write("put [%s] lifecycle rule success" % bucket_name)
  sys.stdout.flush()


def put_bucket_cors_rule(bucket_name, cors_rule):
  check_bucket_name(bucket_name)
  rule = FDSCORSRule(json.loads(cors_rule))
  fds_client.update_cors_rule(bucket_name, rule)
  sys.stdout.write("put [%s] cors rule success" % bucket_name)
  sys.stdout.flush()


def get_bucket_lifecycle_config(bucket_name):
  lifecycle = fds_client.get_lifecycle_config(bucket_name);
  sys.stdout.write(json.dumps(lifecycle))
  sys.stdout.flush()


def get_bucket_cors_config(bucket_name):
  cors = fds_client.get_cors_config(bucket_name)
  sys.stdout.write(json.dumps(cors))
  sys.stdout.flush()


def delete_object(bucket_name, object_name, **kwargs):
  check_bucket_name(bucket_name=bucket_name)
  check_object_name(object_name=object_name)
  fds_client.delete_object(bucket_name=bucket_name,
                           object_name=object_name,
                           **kwargs)
  logger.info('delete object %s success' % (object_name))


def delete_objects(bucket_name, **kwargs):
  check_bucket_name(bucket_name=bucket_name)
  for obj in fds_client.list_all_objects(bucket_name, prefix=kwargs["object_prefix"], delimiter=""):
    fds_client.delete_object(bucket_name=bucket_name,
                             object_name=obj.object_name,
                             **kwargs)
    logger.info('delete object %s success' % (obj.object_name))


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
    for obj in fds_client.list_all_objects(bucket_name, prefix="", delimiter="", is_archive=True):
      fds_client.delete_object(bucket_name, obj.object_name, is_archive=True)
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

def list_bucket_trash(bucket_name=None):
  prefix = bucket_name and bucket_name + "/" or ""

  list_result = fds_client.list_trash_objects(prefix=prefix, delimiter="")

  for i in list_result.common_prefixes:
    sys.stdout.write(i)
    sys.stdout.write('\n')
  for i in list_result.objects:
    sys.stdout.write(i.object_name)
    sys.stdout.write('\n')
  sys.stdout.flush()
  if list_result.is_truncated:
    sys.stdout.write('...\n')

def list_object(bucket_name, object_name_prefix, start_mark='', is_archive=False):
  list_result = fds_client.list_objects(bucket_name=bucket_name,
                                        prefix=object_name_prefix,
                                        delimiter='',
                                        is_archive=is_archive)
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


def list_version_ids(bucket_name, object_name):
  vids = fds_client._list_version_ids_(bucket_name, object_name)
  sys.stdout.write(json.dumps(vids))
  sys.stdout.flush()


def copy_object(src_bucket_name, src_object_name, dst_bucket_name, dst_object_name):
  check_bucket_name(src_bucket_name)
  check_bucket_name(dst_bucket_name)
  check_object_name(src_object_name)
  check_object_name(dst_object_name)

  result = None
  result = fds_client.copy_object(src_bucket_name, src_object_name, dst_bucket_name,
                                  dst_object_name)

  logger.debug("Copy object success")

  if result:
    logger.info('Successfully copy object %s from bucket %s to bucket %s, and rename it to %s' % (
      src_object_name, src_bucket_name, dst_bucket_name, dst_object_name))
  else:
    logger.info('Failed to copy object %s from bucket %s to bucket %s, and rename it to %s' % (
      src_object_name, src_bucket_name, dst_bucket_name, dst_object_name))


def set_bucket_default_webp_quality(bucket_name, webp_quality):
  fds_client._set_bucket_default_webp_quality_(bucket_name, webp_quality)
  res = fds_client._get_bucket_default_webp_quality_(bucket_name)
  if res > 0:
    logger.info("[%s] default webp quality: %d" % (bucket_name, res))
  else:
    logger.info("[%s] is not set convert webp" % bucket_name)


def set_bucket_default_gif_extract_type(bucket_name, gif_extract_type):
  fds_client._set_bucket_default_gif_extract_type_(bucket_name, gif_extract_type)
  res = fds_client._get_bucket_default_gif_extract_type_(bucket_name)
  if res == 'unknown':
    logger.info("[%s] is not set auto gif extract" % (bucket_name))
  else:
    logger.info("[%s] default gif extract type: %s" % (bucket_name, res))


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

  parser.add_argument('--list-trash',
                      action='store_true',
                      dest='list_trash',
                      default=False,
                      help='''If toggled, List trash under current user.''')

  parser.add_argument('-d', '--data',
                      nargs='?',
                      metavar='data file',
                      dest='data_file',
                      help='file to be uploaded or stored')

  parser.add_argument('-D', '--directory',
                      nargs='?',
                      metavar='data dir',
                      dest='data_dir',
                      help="Directory to be uploaded or stored. Use '/' to download all objects under the bucket")

  parser.add_argument('-R', '--recursive',
                      action='store_true',
                      dest='recursive',
                      default=False,
                      help='If toggled, download the directory recursively')

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

  parser.add_argument('--disable_trash',
                      action='store_true',
                      dest='disable_trash',
                      default=False,
                      help='If toggled, delete object without move to trash')

  parser.add_argument('-P', '--object_prefix',
                      nargs='?',
                      metavar="object's prefix",
                      type=str,
                      dest='object_prefix',
                      help="object's prefix")

  parser.add_argument('--lifecycle',
                      nargs='?',
                      metavar='lifecycle config, json format',
                      dest='lifecycle',
                      const=True,
                      default=None,
                      help='''Put or get lifecycle configof the bucket. Please use \\" instead of " in this argument when putting lifecycle config due to shell may eat double quotes.''')

  parser.add_argument('--cors',
                      nargs='?',
                      metavar='cors config, json format',
                      dest='cors',
                      const=True,
                      default=None,
                      help='''Put or get cors config of the bucket. Please use \\" instead of " in this argument when putting cors config due to shell may eat double quotes.''')

  parser.add_argument('--lifecycle-rule',
                      nargs='?',
                      metavar='lifecycle rule, json format',
                      dest='lifecycle_rule',
                      const=True,
                      default=None,
                      help='''Add/update or get one rule of lifecycle config of the bucket. Please use \\" instead of " in this argument when putting lifecycle config due to shell may eat double quotes.''')

  parser.add_argument('--cors-rule',
                      nargs='?',
                      metavar='cors rule, json format',
                      dest='cors_rule',
                      const=True,
                      default=None,
                      help='''Add/update or get one rule of cors config of the bucket. Please use \\" instead of " in this argument when putting cors config due to shell may eat double quotes.''')


  parser.add_argument('--webp-quality',
                       nargs='?',
                       dest='webp_quality',
                       const=-1,
                       default=None,
                       help='Integer indicates webp quality, -1 will disable bucket auto convert webp')

  parser.add_argument('--gif-extract-type',
                      nargs='?',
                      dest='gif_extract_type',
                      const='unknown',
                      default=None,
                      help='String indicates gif extract type, unknown will disable bucket auto gif extract')

  parser.add_argument('--archive',
                      action='store_true',
                      dest='is_archive',
                      default=False,
                      help='''If toggled, visit archived objects.''')

  parser.add_argument('--restore-archive',
                      action='store_true',
                      dest='restore_archive',
                      default=False,
                      help='''If toggled, restore archived object.''')

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
  group.add_argument('--public',
                     action='store_true',
                     dest='is_public',
                     default=False,
                     help='''If toggled, set bucket or object public.''')

  cp = parser.add_argument_group('cp')
  cp.add_argument('-srcb', '--src_bucket',
                  nargs='?',
                  metavar='bucket, name',
                  dest='src_bucket_name',
                  help='Copy object from src_bucket to dst_bucket')
  cp.add_argument('-srco', '--src_object',
                  nargs='?',
                  metavar='object, name',
                  dest='src_object_name',
                  help='Copy object from src_bucket to dst_bucket')
  cp.add_argument('-dstb', '--dst_bucket',
                  nargs='?',
                  metavar='bucket, name',
                  dest='dst_bucket_name',
                  help='Copy object from src_bucket to dst_bucket')
  cp.add_argument('-dsto', '--dst_object',
                  nargs='?',
                  metavar='object, name',
                  dest='dst_object_name',
                  help='Copy object from src_bucket to dst_bucket')

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
                                      enable_cdn_for_upload=enable_cdn,
                                      threshold_size=multipart_upload_threshold_size,
                                      part_size=multipart_upload_buffer_size)
  global end_point
  if not end_point is None:
    fds_config.set_endpoint(end_point)
  global fds_client
  fds_client = GalaxyFDSClient(access_key=access_key,
                               access_secret=secret_key,
                               config=fds_config)

  global force_delete
  global disable_trash
  global object_prefix
  global recursive, webp_quality, gif_extract_type

  try:
    if presigned_url:
      expiration = int(1000 * (float(eval(expiration_in_hour)) * 3600 +
                               float((datetime.utcnow() - datetime(1970, 1, 1, 0, 0, 0,
                                                                   0)).total_seconds())))
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
    elif list_trash:
      list_bucket_trash(bucket_name=bucket_name)
    elif not (list_objects is None):
      if not (bucket_name is None):
        if object_name is not None:
          list_version_ids(bucket_name=bucket_name, object_name=object_name)
        else:
          list_object(bucket_name=bucket_name, object_name_prefix=list_objects,
                      start_mark=start_mark, is_archive=is_archive)
      else:
        list_buckets(fds_client=fds_client, prefix=list_objects, start_mark=start_mark)
      pass
    else:
      if method == 'put':
        if src_bucket_name and src_object_name and dst_bucket_name and dst_object_name:
          copy_object(src_bucket_name, src_object_name, dst_bucket_name, dst_object_name)
        elif object_name:
          if data_dir:
            put_directory(data_dir=data_dir,
                          bucket_name=bucket_name,
                          object_name_prefix=object_name,
                          metadata=metadata)
          elif is_public:
            set_public(bucket_name=bucket_name, object_name=object_name, is_archive=is_archive)
          elif gratee and permission:
            put_object_acl(bucket_name, object_name, gratee, permission, is_archive)
          elif restore_archive:
            restore_archived_object(bucket_name, object_name)
          else:
            put_object(data_file=data_file,
                       bucket_name=bucket_name,
                       object_name=object_name,
                       metadata=metadata,
                       is_archive=is_archive)
        elif is_public:
          set_public(bucket_name=bucket_name)
        elif gratee and permission:
          put_bucket_acl(bucket_name, gratee, permission)
        elif lifecycle:
          put_bucket_lifecycle_config(bucket_name, lifecycle)
        elif lifecycle_rule:
          put_bucket_lifecycle_rule(bucket_name, lifecycle_rule)
        elif cors:
          put_bucket_cors_config(bucket_name, cors)
        elif cors_rule:
          put_bucket_cors_rule(bucket_name, cors_rule)
        elif webp_quality:
          set_bucket_default_webp_quality(bucket_name=bucket_name, webp_quality=webp_quality)
        elif gif_extract_type:
          set_bucket_default_gif_extract_type(bucket_name=bucket_name, gif_extract_type=gif_extract_type)
        else:
          put_bucket(bucket_name)
        pass
      elif method == 'get':
        if object_prefix:
          download_directory(bucket_name=bucket_name, object_prefix=object_prefix,
                             data_dir=data_dir, recursive=recursive)
        elif object_name:
          get_object(data_file=data_file,
                     bucket_name=bucket_name,
                     object_name=object_name,
                     metadata=metadata,
                     offset=offset,
                     length=length,
                     webp_quality=webp_quality,
                     gif_extract_type=gif_extract_type,
                     is_archive=is_archive)
        elif lifecycle:
          get_bucket_lifecycle_config(bucket_name)
        elif cors:
          get_bucket_cors_config(bucket_name)
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
          if gratee and permission:
            delete_object_acl(bucket_name, object_name, gratee, permission, is_archive)
          else:
            delete_object(bucket_name=bucket_name,
                          object_name=object_name,
                          enable_trash=not disable_trash,
                          is_archive=is_archive)
        elif object_prefix is not None:
          delete_objects(bucket_name=bucket_name,
                         object_prefix=object_prefix,
                         enable_trash=not disable_trash)
        elif force_delete:
          delete_bucket_and_objects(bucket_name=bucket_name)
        else:
          if gratee and permission:
            delete_bucket_acl(bucket_name, gratee, permission)
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
