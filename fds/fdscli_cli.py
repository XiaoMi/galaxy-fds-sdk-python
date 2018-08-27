import os
import sys
import logging
import time
import json
import fire
import concurrent.futures

from sys import version_info
from fds import FDSClientConfiguration, GalaxyFDSClient, GalaxyFDSClientException

from fds.fds_cli import read_local_config, multipart_upload_buffer_size, max_upload_retry_time
from fds.model.upload_part_result_list import UploadPartResultList

IS_PY3 = version_info[0] >= 3
log_format = '%(asctime)-15s [%(filename)s:%(lineno)d] %(message)s'
logging.basicConfig(format=log_format)
logger = logging.getLogger('fds.cli')
logger.setLevel(logging.INFO)


def with_exception(func):
    try:
        ret = func()
        return ret
    except Exception as ex:
        e(ex.args)


def e(s):
    print(s)
    sys.exit(1)


def async_task(fds_client, upload_token, part_number, data):
    for i in range(max_upload_retry_time):
        try:
            rtn = fds_client.upload_part(bucket_name=upload_token.bucket_name,
                                         object_name=upload_token.object_name,
                                         upload_id=upload_token.upload_id,
                                         part_number=part_number,
                                         data=data)
            return rtn
        except:
            sleepSeconds = (i + 1) * 10
            logger.warning("upload part %d failed, retry after %d seconds" % (part_number, sleepSeconds))
            time.sleep(sleepSeconds)
            raise GalaxyFDSClientException("Upload part %d failed" % part_number)


class FDSCli(object):
    """
    Advanced fds cli you deserved
    """

    def __init__(self):
        self.__fds_prefix = r'fds://'
        self.__fds_prefix_len = len(self.__fds_prefix)
        self.__local_config = read_local_config()
        self.__access_key_id = self.__parse_access_key_id()
        self.__secret_access_key = self.__parse_access_key_secret()
        self.__endpoint = self.__parse_endpoint()
        logger.debug("endpoint: " + self.__endpoint)

        fds_config = FDSClientConfiguration(region_name="awsde0",
                                            enable_https=False,
                                            enable_cdn_for_download=False,
                                            enable_cdn_for_upload=False,
                                            endpoint=self.__endpoint)
        self.__fds = GalaxyFDSClient(access_key=self.__access_key_id,
                                     access_secret=self.__secret_access_key,
                                     config=fds_config)

    def __parse_access_key_id(self):

        if 'XIAOMI_ACCESS_KEY_ID' in os.environ:
            return os.environ['XIAOMI_ACCESS_KEY_ID']
        elif self.__local_config.get('xiaomi_access_key_id') is not None:
            return self.__local_config.get('xiaomi_access_key_id')
        elif self.__local_config.get('ak') is not None:
            return self.__local_config.get('ak')
        else:
            e("Please set an ACCESS_KEY_ID")

    def __parse_access_key_secret(self):
        if 'XIAOMI_SECRET_ACCESS_KEY' in os.environ:
            return os.environ['XIAOMI_SECRET_ACCESS_KEY']
        elif self.__local_config.get('xiaomi_secret_access_key') is not None:
            return self.__local_config.get('xiaomi_secret_access_key')
        elif self.__local_config.get('sk') is not None:
            return self.__local_config.get('sk')
        else:
            e("Please set a SECRET_ACCESS_KEY")

    def __parse_endpoint(self):
        if self.__local_config.get('xiaomi_fds_endpoint') is not None:
            return self.__local_config.get('xiaomi_fds_endpoint')
        elif self.__local_config.get('end_point') is not None:
            return self.__local_config.get('end_point')
        else:
            e("Please set a FDS_ENDPOINT")

    def mb(self, bucket_uri):
        bucket_name = self.__parse_real_name(bucket_uri)
        with_exception(lambda: self.__fds.create_bucket(bucket_name))
        print("Create bucket %s successfully" % bucket_name)

    def rb(self, bucket_uri, force=False):
        bucket_name = self.__parse_real_name(bucket_uri)

        if force:
            self.__clear_bucket(bucket_name)
        with_exception(lambda: self.__fds.delete_bucket(bucket_name))
        print("Remove bucket %s successfully" % bucket_name)

    def __clear_bucket(self, bucket_name):
        if with_exception(lambda: self.__fds.does_bucket_exist(bucket_name)) is False:
            return
        all_objects = with_exception(lambda: self.__fds.list_all_objects(bucket_name, '', ''))
        names = []
        try:
            for o in all_objects:
                names.append(o.object_name)
        except Exception as ex:
            e(ex.args)
        with_exception(lambda: self.__fds.delete_objects(bucket_name, names))

    def rm(self, bucket_uri, object_name):
        bucket_name = self.__parse_real_name(bucket_uri)

        with_exception(lambda: self.__fds.delete_object(bucket_name, object_name))
        print("Delete object: %s in bucket %s successfully" % (object_name, bucket_name))

    # TODO pprint
    def ls(self, bucket_uri=None):
        if bucket_uri is None:
            buckets = self.__list_buckets()
            for bucket in buckets:
                print(bucket.bucket_name)
        else:
            name = self.__parse_real_name(bucket_uri)
            names = name.split('/')
            result = set()
            if len(names) == 1 or len(names) == 2 and names[1] == '':
                result = self.__list_all_objects(names[0])
            else:
                bucket_name = names[0]
                other = name.split(bucket_name + '/')[1]
                if not name.endswith('/'):
                    o = with_exception(lambda: self.__fds.get_object(bucket_name, other))
                    if o is not None:
                        print(o.summary.object_name)
                else:
                    all_objects = with_exception(lambda: self.__fds.list_all_objects(bucket_name, '', ''))
                    for o in all_objects:
                        object_name = o.object_name
                        if object_name.startswith(other):
                            names = object_name.split(other)[1].split('/')
                            if len(names) == 1:
                                result.add(names[0])
                            else:
                                result.add(names[0] + '/')
            for r in result:
                print(r)

    def __list_buckets(self):
        return with_exception(lambda: self.__fds.list_buckets())

    def __list_all_objects(self, bucket_name):
        all_objects = with_exception(lambda: self.__fds.list_all_objects(bucket_name, '', ''))
        result = set()
        for o in all_objects:
            names = o.object_name.split('/')
            if len(names) == 1:
                result.add(names[0])
            else:
                result.add(names[0] + '/')
        return result

    def cp(self, src, dst):
        is_src_remote = self.__is_bucket_uri(src)
        is_dst_remote = self.__is_bucket_uri(dst)

        if self.__isdir(src):
            e("Source address should be a object")

        if is_src_remote and is_dst_remote:
            src_bucket_name = self.__parse_bucket_name(src)
            src_object_name = self.__parse_object_name(src)
            if src_object_name is None:
                e("%s does contain an object" % src)
            dst_name = self.__parse_real_name(dst)
            dst_bucket_name = self.__parse_bucket_name(dst_name)
            logger.debug("src bucket name " + src_bucket_name)
            logger.debug("dst bucket name " + dst_bucket_name)
            logger.debug("src object name " + src_object_name)
            if self.__isdir(dst_name):
                logger.debug("dst address is a dir")
                dst_object_name = self.__parse_object_name(dst_name) + src_object_name.split('/')[-1]
                logger.debug("dest object name: " + dst_object_name)
            else:
                dst_object_name = self.__parse_object_name(dst_name)
                logger.debug("dest object name: " + dst_object_name)
                if dst_object_name is None:
                    dst_object_name = src.split('/')[-1]
            self.__copy(src_bucket_name, src_object_name, dst_bucket_name, dst_object_name)
            print("Copy object %s from bucket %s to bucket %s, and rename to %s successfully" % (
                src_object_name, src_bucket_name, dst_bucket_name, dst_object_name))
        elif is_src_remote and not is_dst_remote:
            src_bucket_name = self.__parse_bucket_name(src)
            src_object_name = self.__parse_object_name(src)

            logger.debug("src object name=" + src_object_name)
            dst_name = None
            if os.path.isdir(dst):
                if dst == '.' or dst == '..':
                    dst_name = src_object_name.split('/')[-1]
                elif dst.endswith('/'):
                    dst_name = dst + src_object_name.split('/')[-1]
                else:
                    dst_name = dst + '/' + src_object_name.split('/')[-1]
            else:
                dst_name = dst

            self.__download(src_bucket_name, src_object_name, dst_name)
            print("Download object %s from bucket %s to local successfully" % (src_object_name, src_bucket_name))
        elif not is_src_remote and is_dst_remote:
            dst_bucket_name = self.__parse_bucket_name(dst)
            if self.__isdir(dst):
                dst_object_name = self.__parse_object_name(dst) + src.split('/')[-1]
            else:
                dst_object_name = self.__parse_object_name(dst)
                if dst_object_name is None:
                    dst_object_name = src.split('/')[-1]
            logger.debug("dst bucket name: " + dst_bucket_name)
            logger.debug("dst object name: " + dst_object_name)
            logger.debug("upload file is: " + src)
            self.__upload(dst_bucket_name, dst_object_name, src)
            print("Upload object %s to bucket %s successfully" % (src, dst_bucket_name))
        else:
            e("Do not support copy local file to local file")

    def __copy(self, src_bucket_name, src_object_name, dst_bucket_name, dst_object_name):
        with_exception(
            lambda: self.__fds.copy_object(src_bucket_name, src_object_name, dst_bucket_name, dst_object_name))

    def __download(self, bucket_name, object_name, file_name):
        fds_object = with_exception(lambda: self.__fds.get_object(bucket_name=bucket_name,
                                                                  object_name=object_name,
                                                                  stream=True))
        length_left = IS_PY3 and sys.maxsize or sys.maxint
        try:
            with open(file_name, 'wb') as f:
                for chunk in fds_object.stream:
                    l = min(length_left, len(chunk))
                    f.write(chunk[0:l])
                    length_left -= l
                    if length_left <= 0:
                        break
        except Exception as exception:
            print(exception)
        finally:
            fds_object.stream.close()

    # todo concurrency
    def __upload(self, bucket_name, object_name, file_name):
        result = None
        with open(file_name, "rb") as f:
            flen = os.path.getsize(file_name)
            if flen < multipart_upload_buffer_size:
                logger.debug("upload object directly")
                result = with_exception(lambda: self.__fds.put_object(bucket_name=bucket_name,
                                                                      object_name=object_name,
                                                                      data=f,
                                                                      metadata=None))
            else:
                result = self.__upload_concurrency(bucket_name, object_name, f)
        if result is not None:
            print('Put object %s success' % object_name)
        else:
            print('Put object %s failed' % object_name)

    def __upload_concurrency(self, bucket_name, object_name, stream):
        upload_token = None
        logger.debug("bucket name for upload concurrency = " + bucket_name)
        logger.debug("object name for upload concurrency = " + object_name)
        try:
            logger.debug('upload object in multipart upload mode')
            upload_token = self.__fds.init_multipart_upload(bucket_name=bucket_name, object_name=object_name)
            logger.debug("upload id: " + upload_token.upload_id)
            part_number = 1
            futures = []
            result_list = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                while True:
                    data = stream.read(multipart_upload_buffer_size)
                    if len(data) <= 0:
                        break
                    future = executor.submit(async_task, self.__fds, upload_token, part_number, data)
                    futures.append(future)
                    part_number += 1

            for f in concurrent.futures.as_completed(futures):
                result_list.append(f.result())
            upload_part_result = UploadPartResultList({"uploadPartResultList": result_list})
            return self.__fds.complete_multipart_upload(bucket_name=upload_token.bucket_name,
                                                        object_name=upload_token.object_name,
                                                        upload_id=upload_token.upload_id,
                                                        metadata=None,
                                                        upload_part_result_list=json.dumps(upload_part_result))
        except Exception as e:
            print(e)
            with_exception(
                lambda: self.__fds.abort_multipart_upload(bucket_name, object_name, upload_token.upload_id))
            sys.exit(1)

    def mv(self, src, dst):
        is_src_remote = self.__is_bucket_uri(src)

        self.cp(src, dst)
        if is_src_remote:
            self.cp(src, dst)
            bucket_name = self.__parse_bucket_name(src)
            object_name = self.__parse_object_name(src)
            self.__delete_object(bucket_name, object_name)
            print("Delete object %s from bucket %s successfully" % (object_name, bucket_name))
        else:
            logger.debug(src)
            print("Delete local object %s successfully" % src)

    def __delete_object(self, bucket_name, object_name):
        with_exception(lambda: self.__fds.delete_object(bucket_name, object_name))

    @staticmethod
    def __delete_object_local(file_name):
        os.remove(file_name)

    # todo implement
    def sync(self, src, dst, delete=False, exclude=None, include=None):
        e("Not implement")
        if not self.__isdir(src) or not self.__isdir(dst):
            e("sync method only support directory")
        if self.__is_bucket_uri(src) and self.__is_bucket_uri(dst):
            e("sync method only support syncing between local and fds")
        if not self.__is_bucket_uri(src) and not self.__is_bucket_uri(dst):
            e("sync method only support syncing between local and fds")

    def __is_bucket_uri(self, bucket_uri):
        if bucket_uri is not None and len(bucket_uri) > len(self.__fds_prefix):
            return bucket_uri.startswith(self.__fds_prefix)
        return False

    def __parse_real_name(self, bucket_uri):
        if not self.__is_bucket_uri(bucket_uri):
            e("%s is not a valid bucket URI" % bucket_uri)
        return bucket_uri[self.__fds_prefix_len:]

    def __parse_bucket_name(self, bucket):
        real_name = bucket
        if self.__is_bucket_uri(bucket):
            real_name = self.__parse_real_name(bucket)
        return real_name.split('/')[0]

    def __parse_object_name(self, o):
        real_name = o
        if self.__is_bucket_uri(o):
            real_name = self.__parse_real_name(o)
        bucket_name = self.__parse_bucket_name(real_name)
        names = real_name.split(bucket_name + '/')
        if len(names) <= 1:
            return None
        elif len(names):
            return names[1]

    def __is_absolute_bucket(self, name):
        n = self.__parse_object_name(name)
        if n is None:
            return True
        return False

    @staticmethod
    def __isdir(name):
        return name.endswith('/')


def main():
    fire.Fire(FDSCli)


if __name__ == "__main__":
    main()
