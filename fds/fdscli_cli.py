from __future__ import print_function

import concurrent.futures
import errno
import json
import logging
import os
import mimetypes
import sys

try:
    from pathlib import Path
except ImportError:
    from pathlib2 import Path
from pprint import pprint
from sys import version_info

import click
from datetime import datetime


from fds import FDSClientConfiguration, GalaxyFDSClient, GalaxyFDSClientException
from fds.model.fds_object_metadata import FDSObjectMetadata
from fds.utils import rfc822_timestamp, file_md5
from fds.auth.common import Common


IS_PY3 = version_info[0] >= 3

if not IS_PY3:
    input = raw_input

log_format = "%(asctime)-15s [%(filename)s:%(lineno)d] %(message)s"
logging.basicConfig(format=log_format)
logger = logging.getLogger("fds.cli")
logger.setLevel(logging.INFO)

fds_prefix = r"fds://"

fds_client = None
fds_ak = None
fds_sk = None
fds_enable_https = None
fds_enable_cdn_for_download = None
fds_timeout = None
fds_part_size = None
fds_endpoint = None
fds_config = None


def mkdirs(path):
    try:
        if not os.path.isdir(path):
            os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(
            os.path.join(os.path.expanduser("~"), ".config", "xiaomi")
        ):
            pass


class WrongURLFormationException(Exception):
    pass


class WrongEnvironmentException(Exception):
    pass


class LocalConfig(object):
    def __init__(self):
        self.__config_path = os.path.join(
            os.path.expanduser("~"), ".config", "xiaomi", "config"
        )
        mkdirs(os.path.join(os.path.expanduser("~"), ".config", "xiaomi"))

        self.__data = None

        if not os.path.exists(self.__config_path):
            with open(self.__config_path, "w+") as f:
                f.writelines("{}")

        with open(self.__config_path, "r+") as f:
            self.__data = json.load(f)

    @property
    def ak(self):
        return self.__data.get("xiaomi_access_key_id")

    @ak.setter
    def ak(self, value):
        if value is not None and value.strip() != "":
            self.__data["xiaomi_access_key_id"] = value
            self.__dump()

    @property
    def sk(self):
        return self.__data.get("xiaomi_secret_access_key")

    @sk.setter
    def sk(self, value):
        if value is not None and value.strip() != "":
            self.__data["xiaomi_secret_access_key"] = value
            self.__dump()

    @property
    def endpoint(self):
        return self.__data.get("xiaomi_fds_endpoint")

    @endpoint.setter
    def endpoint(self, value):
        if value is not None and value.strip() != "":
            self.__data["xiaomi_fds_endpoint"] = value
            self.__dump()

    def __dump(self):
        with open(self.__config_path, "w") as outfile:
            json.dump(
                self.__data, outfile, sort_keys=True, indent=4, separators=(",", ": ")
            )


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
        content_length = int(metadata.metadata["x-xiaomi-meta-content-length"])
        if human == "k":
            content_length = content_length / 8.0 / 1024
        elif human == "m":
            content_length = content_length / 8.0 / 1024 / 1024
        elif human == "g":
            content_length = content_length / 8.0 / 1024 / 1024 / 1024
        print(
            "{}\t{:.2f}{}\t{}".format(
                metadata.metadata["last-modified"],
                content_length,
                human,
                str(object_name),
            )
        )

    @staticmethod
    def print_lifecycle(lifecycle):
        for action in lifecycle["rules"]:
            pprint(action)
            print("------------------------------------------------")


class FDSURL(object):
    def __init__(self, url):
        if not self.is_fds_url(url):
            raise WrongURLFormationException("Wrong fds url formation")

        self.__url = url
        self.__none_fds_prefix_name = url[len(fds_prefix) :]

    def is_bucket_url(self):
        """
    fds://bucket_name
    fds://bucket_name/
    """
        if (
            self.__none_fds_prefix_name == self.bucket_name()
            or self.__none_fds_prefix_name == self.bucket_name() + "/"
        ):
            return True
        return False

    def bucket_name(self):
        return self.__none_fds_prefix_name.split("/")[0]

    def object_name(self):
        if self.is_dir():
            return None
        if self.is_bucket_url():
            return None
        return self.__none_fds_prefix_name[len(self.bucket_name()) + 1 :]

    def file_name(self):
        if not self.is_object_url():
            return None

        return self.__none_fds_prefix_name.split("/")[-1]

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
        return self.__none_fds_prefix_name[len(self.bucket_name()) + 1 :]

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


class FDSCliGroup(click.Group):
    def __call__(self, *args, **kwargs):
        try:
            return self.main(*args, **kwargs)
        except Exception as e:
            click.echo(str(e))


@click.group(cls=FDSCliGroup)
@click.option("--ak", default=None, help="Access Key ID")
@click.option("--sk", default=None, help="Access Key Secret")
@click.option("--endpoint", default=None, help="FDS Endpoint")
@click.option("--cdn_download", is_flag=True, help="Whether to download using cdn")
@click.option("--https", is_flag=True, help="Whether to download using https")
@click.option("--timeout", default=30, help="Client Timeout")
@click.option(
    "--part_size", default=50 * 1024 * 1024, help="Part size when multipart uploading"
)
@click.pass_context
def cli(ctx, ak, sk, endpoint, https, cdn_download, timeout, part_size):
    ctx.ensure_object(dict)
    global fds_client
    global fds_ak
    global fds_sk
    global fds_endpoint
    global fds_config

    if ctx.invoked_subcommand != "config":
        local_config = LocalConfig()
        env_ak = os.environ.get("FDS_AK")
        env_sk = os.environ.get("FDS_SK")
        env_endpoint = os.environ.get("FDS_ENDPOINT")

        ak = ak or env_ak or local_config.ak
        if not ak:
            raise WrongEnvironmentException(
                "Please setup ak, the loading order is: command line > environment > config file"
            )

        sk = sk or env_sk or local_config.sk
        if not sk:
            raise WrongEnvironmentException(
                "Please setup sk, the loading order is: command line > environment > config file"
            )

        endpoint = endpoint or env_endpoint or local_config.endpoint
        if not endpoint:
            raise WrongEnvironmentException(
                "Please setup endpoint, the loading order is: command line > environment > config file"
            )

        config = FDSClientConfiguration(
            region_name="awsde0",
            enable_https=https,
            enable_cdn_for_download=cdn_download,
            enable_cdn_for_upload=False,
            endpoint=endpoint,
            part_size=part_size,
            timeout=timeout,
        )
        fds_config = config
        fds_ak = ak
        fds_sk = sk
        fds_endpoint = endpoint
        fds_client = GalaxyFDSClient(access_key=ak, access_secret=sk, config=config)


@cli.command()
def config():
    """config ak, sk, endpoint and so on"""
    local_config = LocalConfig()
    default_ak = local_config.ak
    default_sk = local_config.sk
    default_endpoint = local_config.endpoint
    ak = input("enter access key id[default: %s]: " % default_ak)
    if ak == "":
        ak = default_ak
    sk = input("enter secret access key[default: %s]: " % default_sk)
    if sk == "":
        sk = default_sk
    endpoint = input("enter endpoint[default: %s]: " % default_endpoint)
    if endpoint == "":
        endpoint = default_endpoint

    local_config.ak = ak
    local_config.sk = sk
    local_config.endpoint = endpoint


@cli.command()
@click.argument("fds_url")
def mb(fds_url):
    """
  create(make) a bucket
  """
    url = FDSURL(fds_url)
    bucket_name = url.bucket_name()
    fds_client.create_bucket(bucket_name)
    click.echo("create bucket [%s]" % bucket_name)


@cli.command()
@click.argument("fds_url")
@click.option(
    "-f", "--force", help="Delete bucket although it is nonempty", is_flag=True
)
def rb(fds_url, force):
    """
  delete(remove) a bucket
  """
    url = FDSURL(fds_url)
    bucket_name = url.bucket_name()
    if force:
        result = fds_client.list_objects(bucket_name, "", "")
        while True:
            names = []
            for object_summary in result.objects:
                fds_client.delete_object(bucket_name, object_summary.object_name)
                click.echo(
                    "Deleted {}/{}".format(
                        url.bucket_name(), object_summary.object_name
                    )
                )
            if result.is_truncated:
                result = fds_client.list_next_batch_of_objects(result)
            else:
                break

    fds_client.delete_bucket(bucket_name)
    CLIPrinter.done("removed bucket [%s]" % bucket_name)


@cli.command()
@click.argument("fds_url", required=False)
@click.option("-r", "--recursive", default=False, help="Recursively list", is_flag=True)
@click.option("-h", "--human", default="k", help="human should be in 'k|m|g'")
def ls(fds_url, recursive, human):
    """
  list all buckets or objects in a bucket
  """
    if human != "k" and human != "m" and human != "g":
        raise WrongURLFormationException("human should be in 'k|m|g'")

    # bucket_url is None means listing all bucket name
    if fds_url is None:
        buckets = None
        buckets = fds_client.list_authorized_buckets()
        for bucket in buckets:
            click.echo(bucket)
    else:
        delimiter = "/"
        if recursive:
            delimiter = ""

        url = FDSURL(fds_url)
        prefix = url.object_name() or url.object_dir() or ""
        bucket_name = url.bucket_name()
        try:
            results = fds_client.list_all_objects(bucket_name, prefix, delimiter)
            for result in results:
                metadata = fds_client.get_object_metadata(
                    bucket_name, result.object_name
                )
                CLIPrinter.print_object(result.object_name, metadata, human)
        except GalaxyFDSClientException as e:
            click.echo(str(e))


@cli.command()
@click.argument("fds_url")
def rm(fds_url):
    """delete(remove) a object"""
    url = FDSURL(fds_url)

    if url.is_bucket_url():
        raise WrongURLFormationException(
            "The formation must be same as: fds://{bucketname}{objectname}"
        )
    bucket_name = url.bucket_name()
    object_name = url.object_name()

    fds_client.delete_object(bucket_name, object_name)
    click.echo("removed {}/{}".format(bucket_name, object_name))


@cli.command()
@click.argument("fds_url")
@click.option("-e", "--expires", default=1, help="Expiration time")
@click.option("-c", "--cdn", default=False, help="Use cdn url?", is_flag=True)
def presigned(fds_url, expires, cdn):
    """presigned command generates presigned url for download project"""
    url = FDSURL(fds_url)

    if url.is_bucket_url():
        raise WrongURLFormationException(
            "The formation must be same as: fds://{bucketname}/{objectname}"
        )

    bucket_name = url.bucket_name()
    object_name = url.object_name()

    expiration = int(
        1000
        * (
            float(expires) * 3600
            + float(
                (datetime.utcnow() - datetime(1970, 1, 1, 0, 0, 0, 0)).total_seconds()
            )
        )
    )

    if cdn:
        base_uri = fds_config.get_cdn_base_uri()
    else:
        base_uri = fds_config.get_base_uri()
    u = fds_client.generate_presigned_uri(
        base_uri, bucket_name, object_name, expiration
    )
    click.echo("generated presigned url: " + u)


@cli.command()
@click.argument("fds_url")
def show_ttl(fds_url):
    """ttl command shows the lifecycle information of a bucket or a object"""
    url = FDSURL(fds_url)

    bucket_name = url.bucket_name()
    ttl = fds_client.get_lifecycle_config(bucket_name)
    if url.is_bucket_url():
        CLIPrinter.print_lifecycle(ttl)
    elif url.is_object_url():
        if not fds_client.does_object_exists(bucket_name, url.object_name()):
            raise Exception("object {} is not exist".format(url.object_name()))
        if url.is_object_dir():
            prefix = url.object_dir()
        else:
            prefix = url.object_name()
        rules = [rule for rule in ttl["rules"] if rule["prefix"] in prefix]
        CLIPrinter.print_lifecycle({"rules": rules})
    else:
        CLIPrinter.wrong_format()


@cli.command()
@click.argument("fds_url")
@click.option("--public/--no-public", default=True, help="Public or not")
def set_public(fds_url, public):
    """set the resource of fds public or not"""
    url = FDSURL(fds_url)
    if public:
        fds_client.set_public(url.bucket_name(), url.object_name())
    else:
        if url.is_object_dir():
            return
        fds_client.set_private(url.bucket_name(), url.object_name())


@cli.command()
@click.argument("fds_url")
@click.option("--out/--no-out", default=True, help="Outside access")
def access(fds_url, out):
    """set the accessibility of resource"""
    url = FDSURL(fds_url)
    if url.is_bucket_url():
        fds_client.set_bucket_outside_access(url.bucket_name(), out)
    elif url.is_object_url():
        fds_client.set_object_outside_access(url.bucket_name(), url.object_name(), out)
    else:
        raise WrongURLFormationException("Wrong url formation")


@cli.command()
def info():
    """display the configurations"""
    print("Access Key ID: {}".format(fds_ak))
    print("Access Secret Key: {}".format(fds_sk))
    print("Endpoint: {}".format(fds_endpoint))


def _cp(src_url, dst_url):
    src_bucket_name = src_url.bucket_name()
    src_object_name = src_url.object_name()

    dst_bucket_name = dst_url.bucket_name()

    if dst_url.is_object_url():
        dst_object_name = dst_url.object_name()
    else:
        dst_object_name = src_object_name
    fds_client.copy_object(
        src_bucket_name, src_object_name, dst_bucket_name, dst_object_name
    )
    click.echo(
        "copy {}/{} to {}/{}".format(
            src_bucket_name, src_object_name, dst_bucket_name, dst_object_name
        )
    )


def _cp_batch(src_url, dst_url, recursive):
    src_bucket_name = src_url.bucket_name()
    dst_bucket_name = dst_url.bucket_name()

    prefix = ""
    if src_url.is_object_dir():
        prefix = src_url.object_dir()

    delimiter = "/"
    if recursive:
        delimiter = ""

    all_objects = fds_client.list_all_objects(
        bucket_name=src_bucket_name, prefix=prefix, delimiter=delimiter
    )
    for o in all_objects:
        o_name = o.object_name
        fds_client.copy_object(src_bucket_name, o_name, dst_bucket_name, o_name)
        click.echo(
            "copy {}/{} to {}/{}".format(
                src_bucket_name, o_name, dst_bucket_name, o_name
            )
        )


def _download(src_url, dst):
    src_bucket_name = src_url.bucket_name()
    src_object_name = src_url.object_name()

    if os.path.isdir(dst):
        if dst == "." or dst == "..":
            dst_name = src_url.file_name()
        elif dst.endswith("/"):
            dst_name = dst + src_url.file_name()
        else:
            dst_name = dst + "/" + src_object_name.split("/")[-1]
    else:
        dst_name = dst
    mtime = None
    if os.path.isfile(dst_name):
        local_md5 = file_md5(dst_name)
        remote_md5 = fds_client.get_object_metadata(
            src_bucket_name, src_object_name
        ).metadata.get(Common.CONTENT_MD5)
        if remote_md5 is not None and local_md5 == remote_md5:
            CLIPrinter.done(
                "download %s/%s to local(skip because of same md5)"
                % (src_bucket_name, src_object_name)
            )
            return

        mtime = os.path.getmtime(dst_name)

    try:
        fds_object = fds_client.get_object(
            bucket_name=src_bucket_name, object_name=src_object_name, stream=True
        )
    except GalaxyFDSClientException as e:
        CLIPrinter.fail(e.message)
        return
    lm = fds_object.metadata.metadata["last-modified"]
    remote_modified = rfc822_timestamp(lm)

    # if last-modified of local file is not less last-modified of remote file, skip
    if mtime is not None and datetime.fromtimestamp(mtime) >= remote_modified:
        CLIPrinter.done(
            "download %s/%s to local(skip because of updated)"
            % (src_bucket_name, src_object_name)
        )
        return

    length_left = IS_PY3 and sys.maxsize or sys.maxint
    try:
        with open(dst_name, "wb") as f:
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


def _upload(fpath, object_name, dst_url, autodetect_mimetype):
    if not fpath.exists():
        CLIPrinter.warn("{} is a bad file".format(str(fpath)))
        return

    try:
        dst_bucket_name = dst_url.bucket_name()
        dst_object_name = object_name
        if fds_client.does_object_exists(dst_bucket_name, dst_object_name):
            # check md5 firstly
            metadata = fds_client.get_object_metadata(dst_bucket_name, dst_object_name)
            if metadata.metadata.get(Common.CONTENT_MD5) is not None:
                local_md5 = file_md5(str(fpath.resolve()))
                if local_md5 == metadata.metadata.get(Common.CONTENT_MD5):
                    CLIPrinter.done(
                        "upload object %s/%s(skip because of same md5)"
                        % (dst_bucket_name, dst_object_name)
                    )
                    return

            # check last-modified
            mtime = None
            if fpath.is_file():
                mtime = os.path.getmtime(str(fpath.resolve()))

            lm = metadata.metadata[Common.LAST_MODIFIED]
            remote_modified = rfc822_timestamp(lm)

            # if last-modified of local file is not less last-modified of remote file, skip
            if mtime is not None and datetime.fromtimestamp(mtime) <= remote_modified:
                CLIPrinter.done(
                    "upload object %s/%s(skip because of updated)"
                    % (dst_bucket_name, dst_object_name)
                )
                return
    except Exception as e:
        CLIPrinter.fail(e.message)
        return
    mimetype = None
    if autodetect_mimetype:
        mimetype = mimetypes.guess_type(str(fpath.resolve()))[0]
    metadata = FDSObjectMetadata()
    if mimetype is not None:
        metadata.add_header(Common.CONTENT_TYPE, mimetype)

    with open(str(fpath.resolve()), "rb") as f:
        try:
            fds_client.put_object(
                dst_bucket_name, dst_object_name, f, metadata=metadata
            )
            CLIPrinter.done("upload object %s/%s" % (dst_bucket_name, dst_object_name))
        except GalaxyFDSClientException as e:
            CLIPrinter.fail("upload object %s/%s, %s" % (dst_bucket_name, dst_object_name, e.message))


def _upload_batch(s_path, dst_url, concurrency, autodetect_mimetype):
    first_object_name = dst_url.object_dir() or ""
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        for fpath in s_path.glob("**/*"):
            extra_object_name = fpath.relative_to(s_path)
            object_name = str(first_object_name / extra_object_name)
            object_name = "/".join(object_name.split("\\"))
            if fpath.is_file():
                executor.submit(
                    _upload, fpath, object_name, dst_url, autodetect_mimetype
                )


@cli.command()
@click.argument("src")
@click.argument("dst")
@click.option(
    "-a", "--autodetect_mimetype", is_flag=True, help="Whether to autodetect mimetype"
)
def cp(src, dst, autodetect_mimetype):
    """cp command do lots of things.

    \b
    1. rename a fds file from a to b
    2. upload a local file to fds
    3. download a fds file to local
    4. copy a fds file from bucket1 to bucket2
    5. can not handle directory
    """

    if FDSURL.is_fds_url(src) and FDSURL.is_fds_url(dst):
        src_url = FDSURL(src)
        dst_url = FDSURL(dst)

        if not src_url.is_object_url():
            raise WrongURLFormationException(
                "cp command can only handle an existing file"
            )
        _cp(src_url, dst_url)

    elif FDSURL.is_fds_url(src) and not FDSURL.is_fds_url(dst):
        src_url = FDSURL(src)

        if not src_url.is_object_url():
            raise WrongURLFormationException(
                "cp command can only handle an existing file"
            )
        _download(src_url, dst)

    elif not FDSURL.is_fds_url(src) and FDSURL.is_fds_url(dst):
        dst_url = FDSURL(dst)

        if not os.path.isfile(src):
            raise WrongURLFormationException(
                "cp command can only handle an existing file"
            )
        fpath = Path(src)
        if dst_url.is_object_url():
            object_name = dst_url.object_name()
        else:
            object_name = (dst_url.object_dir() or "") + fpath.name
        _upload(
            fpath.resolve(),
            object_name,
            dst_url,
            autodetect_mimetype=autodetect_mimetype,
        )
    else:
        CLIPrinter.fail("don't support copy file from local to local")


@cli.command()
@click.argument("src")
@click.argument("dst")
@click.option(
    "-a", "--autodetect_mimetype", is_flag=True, help="Whether to autodetect mimetype"
)
@click.option("--concurrency", default=1, help="counts of threads")
def sync(src, dst, autodetect_mimetype, concurrency):
    """sync command syncs between (local directory and fds) (fds and local directory)"""

    if FDSURL.is_fds_url(src) and not FDSURL.is_fds_url(dst):
        src_url = FDSURL(src)
        if src_url.is_object_url():
            raise WrongURLFormationException("sync can not handle file")

        src_bucket_name = src_url.bucket_name()
        prefix = src_url.object_dir() or ""
        try:
            all_objects = fds_client.list_all_objects(
                bucket_name=src_bucket_name, prefix=prefix, delimiter=""
            )
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=concurrency
            ) as executor:
                for o in all_objects:
                    o_name = o.object_name[len(prefix):]
                    o_name = o_name[1:] if o_name.startswith("/") else o_name
                    url = FDSURL(fds_prefix + src_bucket_name + "/" + o.object_name)
                    if "/" not in o_name:
                        executor.submit(_download, url, dst)
                    elif url.is_object_url():
                        o_file_name = o_name.split("/")[-1]
                        o_dir = str(Path(dst) / o_name.split(o_file_name)[0])
                        mkdirs(o_dir)
                        executor.submit(_download, url, o_dir)
        except GalaxyFDSClientException as e:
            CLIPrinter.fail(e.message)

    elif not FDSURL.is_fds_url(src) and FDSURL.is_fds_url(dst):
        dst_url = FDSURL(dst)
        s_path = Path(src)
        _upload_batch(s_path.resolve(), dst_url, concurrency, autodetect_mimetype)

    elif FDSURL.is_fds_url(src) and FDSURL.is_fds_url(dst):
        raise WrongURLFormationException(
            "sync command syncs between (local directory and fds) (fds and local directory)"
        )


def main():
    cli(obj={})


if __name__ == "__main__":
    main()

